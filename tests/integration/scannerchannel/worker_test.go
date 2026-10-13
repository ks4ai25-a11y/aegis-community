//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/alpha/worker"
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestClaimedMapCanBeCapturedInPrivateWorkerWorkspace(t *testing.T) {
	f := setup(t)
	enqueue(t, f)
	l, e := f.client.Claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(filepath.Join(f.assetRoot, "fixture"))
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	cfg := workerConfig(t, f)
	s, e := workspace.Begin(cfg.WorkspaceRoot)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	snapshot, e := source.Capture(context.Background(), root, l.Map, s.Path)
	if e != nil {
		t.Fatal(e)
	}
	snapshot.Close()
}

func workerConfig(t *testing.T, f fixture) worker.Config {
	t.Helper()
	src, e := filepath.Abs("../../..")
	if e != nil {
		t.Fatal(e)
	}
	src, e = filepath.EvalSymlinks(src)
	if e != nil {
		t.Fatal(e)
	}
	reg, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return worker.Config{Socket: f.socket, Credential: f.credential, Owner: "owner-a", SourceRoot: src, AssetRoot: f.assetRoot, WorkspaceRoot: filepath.Join(reg, "registry")}
}

func TestWorkerEmptyQueueHasNoExecutionOrAdmission(t *testing.T) {
	f := setup(t)
	r, e := workerConfig(t, f).RunOnce(context.Background())
	if e != nil || r.State != "no_job" || r.Job != "" || len(r.Receipts) != 0 {
		t.Fatal(r, e)
	}
	var n int
	if e = f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n); e != nil || n != 0 {
		t.Fatal("empty worker admitted execution", n, e)
	}
}

func TestWorkerChangedSourceFailsBeforeContainerAndRetainsAdmission(t *testing.T) {
	f := setup(t)
	j := enqueue(t, f)
	if e := os.WriteFile(filepath.Join(f.assetRoot, "fixture/query.py"), []byte("# changed after approved map\n"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := workerConfig(t, f).RunOnce(context.Background())
	if e == nil || r.State != "stopped" || r.Job != j.ID || !r.FailureReported || len(r.Receipts) != 0 {
		t.Fatal(r, e)
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "tool_error" || got.Error != "SOURCE_CAPTURE_FAILED" {
		t.Fatal(got, e)
	}
	assertCleanupHeld(t, f)
}

func TestRealBanditWorkerSubmitsBoundReceiptWithoutCompletingJob(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker scanner fixture acceptance only")
	}
	f := setup(t)
	j := enqueue(t, f)
	r, e := workerConfig(t, f).RunOnce(context.Background())
	if e != nil || r.State != "awaiting_controller_finalization" || r.Job != j.ID || len(r.Receipts) != 1 || r.FailureReported {
		got, _ := f.q.Get("owner-a", j.ID)
		t.Fatal(r, e, got.Error)
	}
	receipts, e := f.q.Receipts("owner-a", j.ID)
	if e != nil || len(receipts) != 1 {
		t.Fatal(receipts, e)
	}
	ex := receipts[0].Document.Execution
	if ex.Tool != "bandit" || ex.Container == "" || ex.Cleanup != "complete" || ex.Status != "completed" || ex.Snapshot.InputMap != f.in.MapDigest {
		t.Fatal("actual pinned execution missing", ex)
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "running" {
		t.Fatal("worker falsely finalized job", got, e)
	}
	assertWorkerAdmissionHeld(t, f)
}

func TestRealWorkerSuiteUsesDistinctJournalsAndIdenticalApprovedInput(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker scanner fixture acceptance only")
	}
	f := setup(t)
	f.in.Tools = []string{"bandit", "gitleaks"}
	j := enqueue(t, f)
	cfg := workerConfig(t, f)
	r, e := cfg.RunOnce(context.Background())
	if e != nil || r.State != "awaiting_controller_finalization" || len(r.Receipts) != 2 {
		t.Fatal(r, e)
	}
	receipts, e := f.q.Receipts("owner-a", j.ID)
	if e != nil || len(receipts) != 2 {
		t.Fatal(receipts, e)
	}
	a, b := receipts[0].Document.Execution, receipts[1].Document.Execution
	if a.Container == "" || a.Container == b.Container || a.Snapshot.Digest != b.Snapshot.Digest || a.Cleanup != "complete" || b.Cleanup != "complete" {
		t.Fatal("suite lost source/container identity", a.Tool, b.Tool)
	}
	entries, e := os.ReadDir(cfg.WorkspaceRoot)
	if e != nil || len(entries) != 1 || entries[0].Name() != ".registry-lock" {
		t.Fatal("suite retained source workspace", entries, e)
	}
	assertWorkerAdmissionHeld(t, f)
}

func assertWorkerAdmissionHeld(t *testing.T, f fixture) {
	t.Helper()
	var n int
	if e := f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n); e != nil || n != 1 {
		t.Fatal("worker released global admission", n, e)
	}
}

func TestRealWorkerMissingOfflineDatabaseStoresToolError(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker scanner fixture acceptance only")
	}
	f := setup(t)
	f.in.Tools = []string{"osv_v2"}
	j := enqueue(t, f)
	r, e := workerConfig(t, f).RunOnce(context.Background())
	if e == nil || r.State != "stopped" || !r.FailureReported || len(r.Receipts) != 1 {
		t.Fatal(r, e)
	}
	receipts, e := f.q.Receipts("owner-a", j.ID)
	if e != nil || len(receipts) != 1 {
		t.Fatal(receipts, e)
	}
	ex := receipts[0].Document.Execution
	if ex.Status != "tool_error" || len(ex.Result.Findings) != 0 || ex.Container != "" && ex.Cleanup != "complete" {
		t.Fatal("missing database became a clean claim", ex.Status, ex.Container)
	}
	assertCleanupHeld(t, f)
}
