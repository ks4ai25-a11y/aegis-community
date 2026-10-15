// SPDX-License-Identifier: Apache-2.0
// Package executor runs only fixed read-only scanner invocations. It is a
// privileged local operator facility, never linked into the public controller.
package executor

import (
	"aegis.local/alpha/scanners"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Tool struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Image   string `json:"image"`
}
type Config struct {
	EngineJournalRoot  string
	LockPath           string
	ExpectedLockDigest string
	RulesPath          string
	ScratchParent      string
	Docker             string
	GuardDir           string
	Deadline           time.Time
	DurationSeconds    int
	BeforeStart        func(string, string) error
	BeforeLaunch       func(Execution, string, string) error
}
type Execution = scanevidence.Execution

var scannerName = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)

var pinnedImage = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$`)

func resolve(path, id string) (Tool, string, error) {
	b, e := readPinnedLockFile(path)
	if e != nil || len(b) > 65536 {
		return Tool{}, "", fmt.Errorf("bounded scanner lock unavailable")
	}
	var lock struct {
		Schema string `json:"schema_version"`
		Tools  []Tool `json:"tools"`
	}
	if json.Unmarshal(b, &lock) != nil || lock.Schema != "1.0" || len(lock.Tools) > 16 {
		return Tool{}, "", fmt.Errorf("invalid tool lock")
	}
	var found Tool
	seen := map[string]bool{}
	for _, tool := range lock.Tools {
		if seen[tool.ID] || !pinnedImage.MatchString(tool.Image) || tool.Version == "" || len(tool.Version) > 64 {
			return Tool{}, "", fmt.Errorf("invalid pinned tool identity")
		}
		seen[tool.ID] = true
		if tool.ID == id {
			found = tool
		}
	}
	if found.ID == "" {
		return Tool{}, "", fmt.Errorf("scanner not pinned")
	}
	return found, source.Hash(b), nil
}

// cappedOutput cancels execution immediately on a stream budget violation.
type cappedOutput struct {
	mu       sync.Mutex
	data     bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	exceeded bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.data.Len()+len(p) > w.limit {
		w.exceeded = true
		w.cancel()
		return 0, fmt.Errorf("scanner output budget exceeded")
	}
	return w.data.Write(p)
}
func (w *cappedOutput) Bytes() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte{}, w.data.Bytes()...), w.exceeded
}

// Run scans an already captured private snapshot. Original checkout paths,
// arbitrary argv and caller environment variables never enter the container.
func (c Config) Run(ctx context.Context, toolID, app, repository string, snapshot source.Snapshot) (out Execution, err error) {
	invocation, e := scanners.BuildInvocation(toolID)
	if e != nil {
		return out, e
	}
	if !c.Deadline.IsZero() && (!c.Deadline.After(time.Now()) || c.Deadline.After(time.Now().Add(15*time.Minute))) {
		return out, fmt.Errorf("scanner deadline invalid or expired")
	}
	tool, lockDigest, e := resolve(c.LockPath, toolID)
	if e != nil {
		return out, e
	}
	if c.ExpectedLockDigest != "" && lockDigest != c.ExpectedLockDigest {
		return out, fmt.Errorf("scanner lock differs from authorized job")
	}
	if os.Geteuid() <= 0 || os.Getegid() < 0 {
		return out, fmt.Errorf("operator scanner execution requires a non-root host identity")
	}
	if app == "" || len(app) > 128 || repository == "" || len(repository) > 128 {
		return out, fmt.Errorf("bounded application and repository identities required")
	}
	if snapshot.Path == "" || strings.ContainsAny(snapshot.Path, ":,") {
		return out, fmt.Errorf("invalid private snapshot mount")
	}
	root, e := os.OpenRoot(snapshot.Path)
	if e != nil {
		return out, e
	}
	defer root.Close()
	if e = source.ValidateSnapshot(ctx, root, snapshot.Manifest); e != nil {
		return out, e
	}
	out = Execution{Parser: scanners.ParserVersion, Invocation: invocation, Profile: "repo_offline-network-none-v1", Schema: "1.0", Tool: tool.ID, Version: tool.Version, Image: strings.Split(tool.Image, "@")[1], LockDigest: lockDigest, Snapshot: snapshot.Manifest, Started: time.Now().UTC().Format(time.RFC3339Nano), Exit: -1, Status: "tool_error", Cleanup: "unconfirmed", Result: scanners.Result{Status: "tool_error", Findings: []scanners.Finding{}, Diagnostics: []scanners.Diagnostic{}}, Limitations: []string{"Read-only tool-reported static claims only; no exploit or remediation proof.", "Protected and generated files excluded by inventory; no complete coverage claim.", "Only operator-launched network-none scanner containers; no arbitrary repository code execution.", "Publisher signatures, licence review, offline advisory database provisioning and full scanner coverage remain pending."}}
	var rules *source.Snapshot
	if toolID == "semgrep_ce" {
		r, e := os.OpenRoot(c.RulesPath)
		if e != nil {
			return out, fmt.Errorf("pinned local rule pack unavailable")
		}
		m, e := source.ReadRootContext(ctx, r, "aegis-rules", "operator-local-rules")
		if e != nil {
			r.Close()
			return out, e
		}
		captured, e := source.Capture(ctx, r, m, c.ScratchParent)
		r.Close()
		if e != nil {
			return out, e
		}
		rules = &captured
		defer func() {
			if out.Container != "" && out.Cleanup != "complete" {
				return
			}
			if e := rules.Close(); e != nil {
				out.Cleanup = "unconfirmed"
				out.Status = "tool_error"
				out.Result.Status = "tool_error"
				out.Result.Findings = []scanners.Finding{}
				err = fmt.Errorf("rule workspace cleanup unconfirmed")
			}
		}()
		out.RulesDigest = rules.Manifest.Digest
		out.Limitations = append(out.Limitations, "The current Semgrep pack contains only the bundled synthetic rule; it is not a general SAST rule suite.")
	}
	docker, endpoint, e := c.engine(ctx)
	if e != nil {
		return out, e
	}
	engineCtx, engineCancel := context.WithTimeout(ctx, 5*time.Second)
	engine, e := inspectOutput(engineCtx, docker, endpoint, 512, "info", "--format", "{{.OSType}} {{.Architecture}} {{.ID}}")
	engineCancel()
	if e != nil || len(engine) > 512 {
		return out, fmt.Errorf("local scanner engine unavailable")
	}
	fields := strings.Fields(string(engine))
	if len(fields) != 3 || fields[0] != "linux" {
		return out, fmt.Errorf("Linux scanner engine required")
	}
	arch := ""
	switch fields[1] {
	case "aarch64", "arm64":
		arch = "arm64"
	case "x86_64", "amd64":
		arch = "amd64"
	default:
		return out, fmt.Errorf("scanner engine architecture unsupported")
	}
	if c.GuardDir == "" {
		return out, fmt.Errorf("independent scanner guard not provisioned")
	}
	guardFile, e := os.Open(filepath.Join(c.GuardDir, "scanner-guard-linux-"+arch))
	if e != nil {
		return out, fmt.Errorf("scanner guard unavailable")
	}
	guardBytes, e := io.ReadAll(io.LimitReader(guardFile, 16<<20+1))
	guardFile.Close()
	if e != nil || len(guardBytes) == 0 || len(guardBytes) > 16<<20 {
		return out, fmt.Errorf("scanner guard budget invalid")
	}
	guardRoot, e := os.MkdirTemp(c.ScratchParent, "aegis-guard-")
	if e != nil {
		return out, e
	}
	defer func() {
		if out.Container != "" && out.Cleanup != "complete" {
			return
		}
		if e := os.RemoveAll(guardRoot); e != nil {
			out.Status = "tool_error"
			out.Cleanup = "unconfirmed"
			out.Result.Status = "tool_error"
			out.Result.Findings = []scanners.Finding{}
			err = fmt.Errorf("guard cleanup unconfirmed")
		}
	}()
	if strings.ContainsAny(guardRoot, ":,") {
		return out, fmt.Errorf("guard mount invalid")
	}
	if e = os.WriteFile(filepath.Join(guardRoot, "scanner-guard"), guardBytes, 0500); e != nil {
		return out, e
	}
	manifestBytes, e := json.Marshal(snapshot.Manifest)
	if e != nil || len(manifestBytes) > scanners.MaxOutput {
		return out, fmt.Errorf("snapshot manifest budget exceeded")
	}
	if e = os.WriteFile(filepath.Join(guardRoot, "input-manifest.json"), manifestBytes, 0400); e != nil {
		return out, e
	}
	if rules != nil {
		b, e := json.Marshal(rules.Manifest)
		if e != nil {
			return out, e
		}
		if e = os.WriteFile(filepath.Join(guardRoot, "rules-manifest.json"), b, 0400); e != nil {
			return out, e
		}
	}
	out.GuardDigest = source.Hash(guardBytes)
	seconds := invocation.TimeoutSeconds
	if c.DurationSeconds != 0 {
		if c.DurationSeconds < 1 || c.DurationSeconds > seconds {
			return out, fmt.Errorf("invalid scanner duration")
		}
		seconds = c.DurationSeconds
	}
	deadline := c.Deadline
	if deadline.IsZero() {
		deadline = time.Now().Add(time.Duration(seconds+5) * time.Second)
	}
	out.DurationLimit = seconds
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return out, e
	}
	name := "aegis-scan-" + hex.EncodeToString(nonce)
	if c.BeforeStart != nil {
		if e = c.BeforeStart(name, source.Hash([]byte(endpoint+"\n"+fields[2]))); e != nil {
			return out, fmt.Errorf("durable workspace binding failed")
		}
	}
	if c.BeforeLaunch != nil {
		if e = c.BeforeLaunch(out, name, source.Hash([]byte(endpoint+"\n"+fields[2]))); e != nil {
			return out, fmt.Errorf("durable scanner launch authorization failed")
		}
	}
	if ctx.Err() != nil || !deadline.After(time.Now()) {
		return out, fmt.Errorf("scanner deadline expired before launch")
	}
	out.Container = name
	uid, gid := strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid())
	args := []string{"run", "--entrypoint", "/aegis/scanner-guard", "--name", name, "--label", "io.aegis.scan=" + name, "--label", "io.aegis.operator_pid=" + strconv.Itoa(os.Getpid()), "--rm", "--pull=never", "--network=none", "--read-only", "--user=" + uid + ":" + gid, "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=768m", "--memory-swap=768m", "--cpus=1", "--log-driver=none", "--tmpfs", "/tmp:rw,noexec,nosuid,size=96m,uid=" + uid + ",gid=" + gid, "-e", "HOME=/tmp", "-e", "SEMGREP_SEND_METRICS=off", "--mount", "type=bind,src=" + snapshot.Path + ",dst=/src,readonly"}
	if rules != nil {
		args = append(args, "--mount", "type=bind,src="+rules.Path+",dst=/rules,readonly")
	}
	args = append(args, "--mount", "type=bind,src="+guardRoot+",dst=/aegis,readonly", tool.Image, tool.ID, strconv.Itoa(seconds), deadline.UTC().Format(time.RFC3339Nano))
	runDeadline := time.Now().Add(time.Duration(seconds+5) * time.Second)
	if deadline.Before(runDeadline) {
		runDeadline = deadline
	}
	runCtx, cancel := context.WithDeadline(ctx, runDeadline)
	defer cancel()
	stdout := &cappedOutput{limit: invocation.MaxOutput, cancel: cancel}
	stderr := &cappedOutput{limit: invocation.MaxOutput, cancel: cancel}
	var runErr error
	if c.EngineJournalRoot != "" {
		rulesPath := ""
		if rules != nil {
			rulesPath = rules.Path
		}
		options := sdkCreateOptions(tool, name, snapshot.Path, rulesPath, guardRoot, seconds, deadline)
		result := c.runEngineSDK(runCtx, endpoint, source.Hash([]byte(endpoint+"\n"+fields[2])), name, options, stdout, stderr, cancel)
		runErr = result.err
		out.Duration = result.duration
		out.Exit = result.exit
		if result.err != nil {
			out.Exit = -1
		}
		if !result.cleanup {
			return out, fmt.Errorf("tracked scanner engine cleanup unconfirmed")
		}
		out.Cleanup = "complete"
	} else {
		command := engineCommand(runCtx, docker, endpoint, args...)
		command.Stdout = stdout
		command.Stderr = stderr
		started := time.Now()
		runErr = command.Run()
		out.Duration = time.Since(started).Milliseconds()
		if command.ProcessState != nil {
			out.Exit = command.ProcessState.ExitCode()
		}
		// Cancelling the Docker CLI alone does not kill a container. Always remove
		// the exact randomly named cgroup and prove it is absent before returning.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		remove := engineCommand(cleanupCtx, docker, endpoint, "rm", "--force", "--volumes", name)
		remove.Stdout = nil
		remove.Stderr = nil
		_ = remove.Run()
		remaining, e := inspectOutput(cleanupCtx, docker, endpoint, 512, "ps", "--all", "--filter", "label=io.aegis.scan="+name, "--format", "{{.ID}}")
		if e != nil || len(bytes.TrimSpace(remaining)) != 0 {
			return out, fmt.Errorf("scanner container cleanup unconfirmed")
		}
		out.Cleanup = "complete"

	}
	raw, stdoutExceeded := stdout.Bytes()
	_, stderrExceeded := stderr.Bytes()
	if stdoutExceeded || stderrExceeded {
		out.Result.Diagnostics = []scanners.Diagnostic{{Code: "OUTPUT_LIMIT", Message: "Scanner stream exceeded its bound; no zero-findings claim."}}
		return out, nil
	}
	if runCtx.Err() != nil {
		out.Result.Diagnostics = []scanners.Diagnostic{{Code: "CANCELLED_OR_TIMEOUT", Message: "Scanner cancelled or timed out; no complete result."}}
		return out, nil
	}
	allowed := false
	for _, code := range invocation.FindingExitCodes {
		if code == out.Exit {
			allowed = true
		}
	}
	if out.Exit == 124 {
		out.Result.Diagnostics = []scanners.Diagnostic{{Code: "SCANNER_DEADLINE", Message: "Independent scanner guard interrupted execution; no complete result."}}
		return out, nil
	}
	if !allowed || runErr != nil && out.Exit < 0 {
		out.Result.Diagnostics = []scanners.Diagnostic{{Code: "TOOL_EXIT", Message: "Scanner failed or required offline data was unavailable; no zero-findings claim."}}
		return out, nil
	}
	salt := make([]byte, 32)
	if _, e = rand.Read(salt); e != nil {
		return out, e
	}
	result, parseErr := scanners.Parse(toolID, raw, scanners.Job{App: app, Repository: repository, InputDigest: snapshot.Manifest.Digest, ToolVersion: tool.Version, ImageDigest: out.Image, SecretSalt: salt})
	// A finding may reference only a file that actually belonged to this input.
	paths := map[string]bool{}
	for _, file := range snapshot.Manifest.Files {
		paths[file.Path] = true
	}
	for _, finding := range result.Findings {
		if finding.Path != "" && !paths[finding.Path] {
			parseErr = fmt.Errorf("finding outside captured input")
		}
	}
	if parseErr != nil {
		out.Result.Diagnostics = []scanners.Diagnostic{{Code: "INVALID_OUTPUT", Message: "Scanner result identity, path or format invalid; no zero-findings claim."}}
		return out, nil
	}
	out.Status = result.Status
	out.Result = result
	return out, nil
}
