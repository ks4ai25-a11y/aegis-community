// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package executor

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/source"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealSDKGuardDeadlineExitIsCollectedBeforeAutoRemoval(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker guard fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cfg := Config{}
	docker, endpoint, e := cfg.engine(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := inspectOutput(ctx, docker, endpoint, 512, "info", "--format", "{{.OSType}} {{.Architecture}} {{.ID}}")
	fields := strings.Fields(string(raw))
	if e != nil || len(fields) != 3 || fields[0] != "linux" {
		t.Fatal("local Linux engine required")
	}
	arch := fields[1]
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	guard, e := os.ReadFile("../../bin/scanner-guard-linux-" + arch)
	if e != nil {
		t.Fatal(e)
	}
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	dir := filepath.Join(parent, "guard")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "scanner-guard"), guard, 0500); e != nil {
		t.Fatal(e)
	}
	cfg.EngineJournalRoot = filepath.Join(parent, "journal")
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-" + hex.EncodeToString(random)
	engine := source.Hash([]byte(endpoint + "\n" + fields[2]))
	tool, _, e := resolve("../../tools/scanners.lock.json", "bandit")
	if e != nil {
		t.Fatal(e)
	}
	options := sdkCreateOptions(tool, name, dir, "", dir, 120, time.Now().Add(-time.Second), nil)
	out := cfg.runEngineSDK(ctx, endpoint, engine, name, options, io.Discard, io.Discard, cancel)
	if out.err != nil || !out.cleanup || out.exit != 124 {
		t.Fatalf("real SDK guard lifecycle: exit=%d cleanup=%t error=%v", out.exit, out.cleanup, out.err)
	}
	state := journalState(t, cfg.EngineJournalRoot, engine)
	b, _ := json.Marshal(map[string]any{"exit_code": out.exit, "local_cleanup_observed": out.cleanup, "guard_digest": source.Hash(guard), "image": tool.Image, "journal": state})
	t.Logf("REAL_SDK_DEADLINE_PROBE %s", b)
}

func TestRealJournaledOperatorCLIAndReadOnlyStatus(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker scanner fixture only")
	}
	parent, e := os.MkdirTemp("", "aegis-journal-cli-")
	if e != nil {
		t.Fatal(e)
	}
	parent, e = filepath.EvalSymlinks(parent)
	if e != nil {
		t.Fatal(e)
	}
	settled := false
	defer func() {
		if settled {
			os.RemoveAll(parent)
		}
	}()
	repo := filepath.Join(parent, "repo")
	os.Mkdir(repo, 0700)
	if e = os.WriteFile(filepath.Join(repo, "query.py"), []byte("def unsafe(code):\n    return eval(code)\n"), 0600); e != nil {
		t.Fatal(e)
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	journal := filepath.Join(parent, "journal")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin/aegis-research"), "scan-offline-journaled", "bandit", repo, root, journal)
	cmd.Env = append(os.Environ(), "TMPDIR="+parent)
	output, e := cmd.Output()
	var execution Execution
	if json.Unmarshal(output, &execution) != nil {
		t.Fatal("CLI did not return bounded execution")
	}
	settled = execution.Container == "" || execution.Cleanup == "complete"
	if e != nil || execution.Cleanup != "complete" || execution.Status != "completed" || len(execution.Result.Findings) != 1 {
		t.Fatal("journaled CLI did not retain static evidence", execution.Status, execution.Cleanup, e)
	}
	// Read only the digest-bound manifest to select this fixture's engine. The
	// public status response excludes paths and cannot clear pending requests.
	manifest, e := os.ReadFile(filepath.Join(journal, execution.Container, "attempt.json"))
	if e != nil {
		t.Fatal(e)
	}
	var m struct {
		Document struct {
			Engine string `json:"engine_digest"`
		} `json:"document"`
	}
	if json.Unmarshal(manifest, &m) != nil {
		t.Fatal("fixture manifest")
	}
	statusCmd := exec.CommandContext(ctx, filepath.Join(root, "bin/aegis-research"), "engine-journal-status", journal, m.Document.Engine)
	status, e := statusCmd.Output()
	if e != nil {
		t.Fatal("status CLI failed")
	}
	var observation enginejournal.Observation
	if json.Unmarshal(status, &observation) != nil || observation.Attempts != 1 || observation.Unresolved != 0 || observation.Unfinished != 0 || observation.CleanupAuthorized || observation.ControllerBound || observation.ExclusiveOrigin {
		t.Fatal("status CLI invented authority")
	}
	t.Logf("REAL_JOURNALED_CLI_EXECUTION %s", output)
	t.Logf("REAL_JOURNALED_CLI_STATUS %s", status)
}

func TestRealSDKCreatedSandboxMatchesOriginalEngineObserver(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned stopped-container fixture only")
	}
	host, contextName := os.Getenv("DOCKER_HOST"), os.Getenv("DOCKER_CONTEXT")
	cfg, expected, metadata, _ := sandboxObservationFixture(t)
	t.Setenv("DOCKER_HOST", host)
	t.Setenv("DOCKER_CONTEXT", contextName)
	cfg.Docker = "docker"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	docker, endpoint, e := cfg.engine(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := inspectOutput(ctx, docker, endpoint, 512, "info", "--format", "{{.OSType}} {{.Architecture}} {{.ID}}")
	fields := strings.Fields(string(raw))
	if e != nil || len(fields) != 3 || fields[0] != "linux" {
		t.Fatal("local Linux engine required")
	}
	arch := fields[1]
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	guard, e := os.ReadFile("../../bin/scanner-guard-linux-" + arch)
	if e != nil {
		t.Fatal(e)
	}
	guardDir := metadata.Mounts[1].Source
	guardPath := filepath.Join(guardDir, "scanner-guard")
	os.Chmod(guardPath, 0700)
	if e = os.WriteFile(guardPath, guard, 0500); e != nil {
		t.Fatal(e)
	}
	os.Chmod(guardPath, 0500)
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-" + hex.EncodeToString(random)
	document := expected.Launch.Document
	document.Plan.Container = name
	document.Plan.Engine = source.Hash([]byte(endpoint + "\n" + fields[2]))
	document.Plan.Architecture = arch
	document.Plan.Guard = source.Hash(guard)
	encoded, _ := json.Marshal(document)
	expected.Launch.Digest = source.Hash(encoded)
	expected.Launch.Document = document
	tool, _, e := resolve(cfg.LockPath, "bandit")
	if e != nil {
		t.Fatal(e)
	}
	var id string
	sdk, e := newEngineSDK(endpoint, name, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer sdk.Close()
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = engineCommand(cleanup, docker, endpoint, "rm", "--force", "--volumes", name).Run()
		absent, e := cfg.ContainerAbsent(cleanup, name, document.Plan.Engine)
		if e != nil || !absent {
			t.Error("owned SDK fixture absence unconfirmed")
		}
	})
	capture := &responseCapture{operation: "create", name: name}
	createCtx := context.WithValue(ctx, captureKey{}, capture)
	deadline, e := time.Parse(time.RFC3339Nano, document.Deadline)
	if e != nil {
		t.Fatal(e)
	}
	created, e := sdk.ContainerCreate(createCtx, sdkCreateOptions(tool, name, metadata.Mounts[0].Source, "", guardDir, 120, deadline, nil))
	if e != nil || !observedCreate(capture, created.ID) {
		t.Fatal("owned SDK profile fixture creation failed")
	}
	id = created.ID
	observation, e := cfg.InspectSandbox(ctx, expected)
	if e != nil || observation.State != "created" || !observation.MetadataMatched || !observation.GuardMatched || !observation.SourceMatched || observation.CleanupConfirmed || observation.AuthorityVerified {
		t.Fatal("SDK fixed profile did not match independent read", observation.Code)
	}
	b, _ := json.Marshal(observation)
	t.Logf("REAL_SDK_SANDBOX_OBSERVATION %s", b)
}
