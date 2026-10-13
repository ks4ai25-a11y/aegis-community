// SPDX-License-Identifier: Apache-2.0
// Package worker executes owner-authorized static scans through the private
// channel. It has no controller database access or arbitrary command facility.
package worker

import (
	"aegis.local/alpha/executor"
	"aegis.local/alpha/workerchannel"
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ErrRun = errors.New("authorized scanner worker stopped; controller cleanup admission remains held")
var assetName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// All paths are operator provisioned. The claim contains only a mounted asset
// identifier; it cannot supply a filesystem path, command, URL or image.
type Config struct {
	Socket, Credential, Owner            string
	SourceRoot, AssetRoot, WorkspaceRoot string
}
type Report struct {
	Schema          string                                 `json:"schema_version"`
	Job             string                                 `json:"job_id,omitempty"`
	Request         string                                 `json:"request_digest,omitempty"`
	State           string                                 `json:"state"`
	Receipts        []workerchannel.ReceiptAcknowledgement `json:"receipts"`
	FailureReported bool                                   `json:"failure_reported"`
	Result          *workerchannel.SuiteResult             `json:"result,omitempty"`
}

func canonicalDir(path string) bool {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || resolved != path {
		return false
	}
	info, e := os.Stat(path)
	return e == nil && info.IsDir()
}

// openAsset rejects symlinks and checks the opened directory identity. The
// os.Root handle confines subsequent inventory reads if the host renames it.
func openAsset(root *os.Root, ref string) (*os.Root, error) {
	name, ok := strings.CutPrefix(ref, "mounted-asset:")
	if !ok || !assetName.MatchString(name) {
		return nil, ErrRun
	}
	before, e := root.Lstat(name)
	if e != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrRun
	}
	opened, e := root.OpenRoot(name)
	if e != nil {
		return nil, ErrRun
	}
	after, e := opened.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		opened.Close()
		return nil, ErrRun
	}
	return opened, nil
}

// RunOnce claims at most one job and requests controller derivation from its
// accepted receipts. A terminal scan result never verifies or releases cleanup.
func (cfg Config) RunOnce(ctx context.Context) (Report, error) {
	out := Report{Schema: "1.0", State: "not_claimed", Receipts: []workerchannel.ReceiptAcknowledgement{}}
	if !canonicalDir(cfg.SourceRoot) || !canonicalDir(cfg.AssetRoot) {
		return out, ErrRun
	}
	f, e := os.Open(filepath.Join(cfg.SourceRoot, "tools/scanners.lock.json"))
	if e != nil {
		return out, ErrRun
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	if e != nil || len(b) > 65536 {
		return out, ErrRun
	}
	lock := source.Hash(b)
	client, e := workerchannel.New(cfg.Socket, cfg.Credential, cfg.Owner, lock)
	if e != nil {
		return out, ErrRun
	}
	defer client.Close()
	assets, e := os.OpenRoot(cfg.AssetRoot)
	if e != nil {
		return out, ErrRun
	}
	defer assets.Close()
	l, e := client.Claim(ctx)
	if errors.Is(e, workerchannel.ErrEmpty) {
		out.State = "no_job"
		return out, nil
	}
	if e != nil {
		return out, ErrRun
	}
	out.Job, out.Request, out.State = l.Job.ID, l.Job.RequestDigest, "stopped"
	registry := cfg.WorkspaceRoot
	if registry == "" {
		registry = workspace.DefaultRoot()
	}
	failure := "SCANNER_EXECUTION_FAILED"
	captureRemaining := 60 * time.Second
	e = client.RunWithLease(ctx, l, func(run context.Context) error {
		for _, tool := range l.Job.Input.Tools {
			if client.Guard(run, l) != nil {
				return ErrRun
			}
			failure = "SOURCE_CAPTURE_FAILED"
			root, e := openAsset(assets, l.Map.SourceRef)
			if e != nil {
				return ErrRun
			}
			session, e := workspace.Begin(registry)
			if e != nil {
				root.Close()
				return ErrRun
			}
			captureCtx, cancel := context.WithTimeout(run, captureRemaining)
			started := time.Now()
			snapshot, e := source.Capture(captureCtx, root, l.Map, session.Path)
			captureRemaining -= time.Since(started)
			cancel()
			root.Close()
			if e != nil {
				session.Close()
				return ErrRun
			}
			failure = "SCANNER_EXECUTION_FAILED"
			ex := executor.Config{LockPath: filepath.Join(cfg.SourceRoot, "tools/scanners.lock.json"), ExpectedLockDigest: l.Job.LockDigest, RulesPath: filepath.Join(cfg.SourceRoot, "alpha/rules"), GuardDir: filepath.Join(cfg.SourceRoot, "bin"), ScratchParent: session.Path, DurationSeconds: l.Job.Input.Duration, BeforeLaunch: func(prepared executor.Execution, name, engine string) error {
				if client.Guard(run, l) != nil {
					return ErrRun
				}
				if e := session.Bind(name, engine); e != nil {
					return ErrRun
				}
				registryDigest := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + filepath.Dir(session.Path) + "\n" + fmt.Sprint(os.Geteuid())))
				_, e := client.RegisterLaunch(run, l, scanevidence.LaunchPlan{Tool: tool, Container: name, Engine: engine, Workspace: filepath.Base(session.Path), Registry: registryDigest, Snapshot: prepared.Snapshot.Digest}, prepared.Version, prepared.Image)
				return e
			}}
			result, runErr := ex.Run(run, tool, l.Job.Input.App, l.Job.Input.Repository, snapshot)
			if result.Container != "" && result.Cleanup != "complete" {
				session.Preserve()
				return ErrRun
			}
			// No container launched, or the exact container was confirmed absent.
			// Workspace removal must also succeed before advancing to another tool.
			if snapshot.Close() != nil {
				session.Preserve()
				return ErrRun
			}
			if session.Close() != nil {
				session.Preserve()
				return ErrRun
			}
			if result.Schema == "" {
				failure = "TOOL_UNAVAILABLE"
				return ErrRun
			}
			ack, e := client.SubmitReceipt(run, l, result)
			if e != nil {
				return ErrRun
			}
			out.Receipts = append(out.Receipts, ack)
			if runErr != nil && result.Status != "tool_error" {
				return ErrRun
			}
		}
		return nil
	})
	if e != nil {
		// This bounded report is not execution authority. Revoked or expired
		// capabilities are still refused by the controller, preserving uncertainty.
		reportCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out.FailureReported = client.Fail(reportCtx, l, failure) == nil
		cancel()
		return out, ErrRun
	}
	finished, e := client.Finish(ctx, l, out.Receipts)
	if e != nil {
		out.State = "finalization_unconfirmed"
		return out, ErrRun
	}
	out.Result = &finished
	out.State = finished.Document.Status
	if finished.Document.ToolError {
		return out, ErrRun
	}
	return out, nil
}
