//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scannerchannelacceptance

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/worker"
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"context"
	"encoding/json"
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

func TestRealBanditWorkerFinalizesBoundResultWithoutReleasingCleanup(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker scanner fixture acceptance only")
	}
	f := setupSource(t, []byte("def unsafe(code):\n    return eval(code)\n"))
	j := enqueue(t, f)
	r, e := workerConfig(t, f).RunOnce(context.Background())
	if e != nil || r.State != "completed" || r.Job != j.ID || len(r.Receipts) != 1 || r.FailureReported {
		failedReceipts, _ := f.q.Receipts("owner-a", j.ID)
		for _, receipt := range failedReceipts {
			ex := receipt.Document.Execution
			codes := []string{}
			for _, d := range ex.Result.Diagnostics {
				codes = append(codes, d.Code)
			}
			t.Logf("FAILED_SCANNER_METADATA tool=%s exit=%d duration_ms=%d status=%s guard=%s codes=%v", ex.Tool, ex.Exit, ex.Duration, ex.Status, ex.GuardDigest, codes)
		}
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
	if len(ex.Result.Findings) == 0 || r.Result == nil || r.Result.Document.FindingClaims != len(ex.Result.Findings) {
		t.Fatal("seeded scanner claims lost during terminal derivation")
	}
	for _, finding := range ex.Result.Findings {
		if finding.Tier != "T0" || finding.Status != "suspected" {
			t.Fatal("real static claim was promoted")
		}
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "completed" {
		t.Fatal("worker did not finalize accepted receipts", got, e)
	}
	assertWorkerAdmissionHeld(t, f)
	assertRecordedLaunches(t, f, j.ID)
	logWorkerResult(t, r)
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
	if e != nil || r.State != "completed" || len(r.Receipts) != 2 {
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
	assertRecordedLaunches(t, f, j.ID)
	logWorkerResult(t, r)
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
	f.in.Tools = []string{"bandit", "osv_v2", "trivy"}
	j := enqueue(t, f)
	r, e := workerConfig(t, f).RunOnce(context.Background())
	if e == nil || r.State != "tool_error" || r.Result == nil || r.FailureReported || len(r.Receipts) != 3 {
		t.Fatal(r, e)
	}
	receipts, e := f.q.Receipts("owner-a", j.ID)
	if e != nil || len(receipts) != 3 {
		t.Fatal(receipts, e)
	}
	ex := receipts[1].Document.Execution
	if ex.Status != "tool_error" || len(ex.Result.Findings) != 0 || ex.Container != "" && ex.Cleanup != "complete" {
		t.Fatal("missing database became a clean claim", ex.Status, ex.Container)
	}
	assertCleanupHeld(t, f)
	if r.Result.Document.Tools[0].Status != "completed" || !r.Result.Document.ToolError {
		t.Fatal("failed tool prevented full suite derivation")
	}
	assertRecordedLaunches(t, f, j.ID)
	logWorkerResult(t, r)
}

func logWorkerResult(t *testing.T, r worker.Report) {
	t.Helper()
	b, e := json.Marshal(r.Result)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("SUITE_RESULT %s", b)
}

func assertRecordedLaunches(t *testing.T, f fixture, job string) {
	t.Helper()
	assertOwnerHTTPResult(t, f, job)
	launches, e := f.q.Launches("owner-a", job)
	if e != nil || len(launches) != len(f.in.Tools) {
		t.Fatal("actual attempted launches not recorded", e)
	}
	receipts, e := f.q.Receipts("owner-a", job)
	if e != nil || len(receipts) != len(launches) {
		t.Fatal("launch receipt correspondence lost", e)
	}
	workspaces, e := f.q.Workspaces("owner-a", job)
	if e != nil || len(workspaces) != len(launches) {
		t.Fatal("actual workspace reservations missing", e)
	}
	for i, l := range launches {
		reserved := workspaces[i]
		if reserved.Document.Plan.Tool != l.Document.Plan.Tool || reserved.Document.Plan.Workspace != l.Document.Plan.Workspace || reserved.Document.Plan.Registry != l.Document.Plan.Registry || reserved.Document.Plan.Snapshot != l.Document.Plan.Snapshot {
			t.Fatal("launch detached from workspace reservation")
		}
		b, e := json.Marshal(reserved)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("WORKSPACE_RECORD %s", b)
		ex := receipts[i].Document.Execution
		if l.Document.Schema != "1.1" || l.Document.GuardSet != f.q.Guards.Digest || l.Document.GuardProtocol != "absolute-deadline-v1" || l.Document.Plan.Guard != ex.GuardDigest || f.q.Guards.Architecture(ex.GuardDigest) != l.Document.Plan.Architecture || l.Document.Plan.Container != ex.Container || l.Document.Plan.Snapshot != ex.Snapshot.Digest || l.Document.Image != ex.Image || l.Document.Version != ex.Version {
			t.Fatal("real receipt detached from its launch", l.Document.Plan.Tool)
		}
		if i > 0 && (l.Document.Plan.Engine != launches[0].Document.Plan.Engine || l.Document.Plan.Registry != launches[0].Document.Plan.Registry) {
			t.Fatal("suite changed execution namespace")
		}
		b, e = json.Marshal(l)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("LAUNCH_RECORD %s", b)
	}
}

func TestRealJournaledWorkerSuiteRetainsControllerCleanupAdmission(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker scanner fixture acceptance only")
	}
	f := setupSourceWithManifest(t, []byte("def unsafe(code):\n    return eval(code)\n"), []byte(`{"name":"owned-journal-fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"owned-journal-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}`))
	f.in.Tools = []string{"bandit", "gitleaks", "osv_v2", "semgrep_ce", "syft", "trivy"}
	job := enqueue(t, f)
	cfg := workerConfig(t, f)
	cfg.EngineJournalRoot = filepath.Join(filepath.Dir(cfg.WorkspaceRoot), "engine-journal")
	report, e := cfg.RunOnce(context.Background())
	if e == nil || report.State != "tool_error" || report.Result == nil || len(report.Receipts) != 6 {
		launches, _ := f.q.Launches("owner-a", job.ID)
		if len(launches) > 0 {
			if j, je := enginejournal.Open(cfg.EngineJournalRoot, launches[0].Document.Plan.Engine); je == nil {
				t.Logf("FAILED_JOURNAL_STATE %+v", j.Observe())
				j.Close()
			}
			entries, _ := os.ReadDir(filepath.Join(cfg.EngineJournalRoot, launches[0].Document.Plan.Container))
			for _, entry := range entries {
				t.Logf("FAILED_JOURNAL_RECORD %s", entry.Name())
			}
		}
		t.Fatal("offline database absence must remain explicit", report, e)
	}
	receipts, e := f.q.Receipts("owner-a", job.ID)
	if e != nil || len(receipts) != 6 {
		t.Fatal(e)
	}
	engine := ""
	for _, receipt := range receipts {
		ex := receipt.Document.Execution
		if ex.Container == "" || ex.Cleanup != "complete" {
			t.Fatal("unconfirmed journaled execution", ex.Tool, ex.Status, ex.Cleanup)
		}
		if ex.Tool == "osv_v2" || ex.Tool == "trivy" {
			if ex.Status != "tool_error" && ex.Status != "completed_stale_db" {
				t.Fatal("unproven offline database promoted", ex.Tool, ex.Status)
			}
		} else if ex.Status != "completed" {
			t.Fatal("fixed scanner failed", ex.Tool, ex.Status, ex.Exit)
		}
		b, _ := json.Marshal(receipt)
		t.Logf("JOURNALED_RECEIPT %s", b)
	}
	launches, e := f.q.Launches("owner-a", job.ID)
	if e != nil || len(launches) != 6 {
		t.Fatal(e)
	}
	engine = launches[0].Document.Plan.Engine
	journal, e := enginejournal.Open(cfg.EngineJournalRoot, engine)
	if e != nil {
		t.Fatal(e)
	}
	state := journal.Observe()
	journal.Close()
	if state.Attempts != 6 || state.Unresolved != 0 || state.Unfinished != 0 || state.CleanupAuthorized || state.ControllerBound || state.ExclusiveOrigin {
		t.Fatal("local journal changed authority", state)
	}
	b, _ := json.Marshal(state)
	t.Logf("ENGINE_JOURNAL_OBSERVATION %s", b)
	entries, e := os.ReadDir(cfg.WorkspaceRoot)
	if e != nil || len(entries) != 1 || entries[0].Name() != ".registry-lock" {
		t.Fatal("source workspace remained", e)
	}
	assertCleanupHeld(t, f)
	assertRecordedLaunches(t, f, job.ID)
	logWorkerResult(t, report)
}
