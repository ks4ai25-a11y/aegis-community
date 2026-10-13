// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func launchFixture(t *testing.T) (*Queue, Lease, scanevidence.Execution, scanevidence.LaunchPlan) {
	q, l, r, _ := receiptFixture(t, "bandit")
	r.Status = "completed"
	r.Result.Status = "completed"
	r.Exit = 0
	r.DurationLimit = l.Job.Input.Duration
	r.Container = "aegis-scan-" + strings.Repeat("a", 32)
	r.GuardDigest = domain.Hash([]byte("guard"))
	r.Cleanup = "complete"
	p := scanevidence.LaunchPlan{Guard: q.Guards.AMD64, Architecture: "amd64", Tool: r.Tool, Container: r.Container, Engine: domain.Hash([]byte("engine")), Workspace: "run-" + strings.Repeat("a", 32), Registry: domain.Hash([]byte("registry")), Snapshot: r.Snapshot.Digest}
	reserveLaunchWorkspace(t, q, l, p)
	return q, l, r, p
}

func reserveLaunchWorkspace(t *testing.T, q *Queue, l Lease, p scanevidence.LaunchPlan) {
	t.Helper()
	if _, e := q.ReserveWorkspace(l, scanevidence.WorkspacePlan{Tool: p.Tool, Workspace: p.Workspace, Registry: p.Registry, Snapshot: p.Snapshot}); e != nil {
		t.Fatal(e)
	}
}

func TestLaunchIsImmutableAuditedAndReplayRequiresLiveLease(t *testing.T) {
	q, l, _, p := launchFixture(t)
	got, e := q.RegisterLaunch(l, p)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := q.RegisterLaunch(l, p)
	if e != nil || replay.Digest != got.Digest {
		t.Fatal("live registration replay changed attempt", e)
	}
	for _, statement := range []string{"UPDATE scanner_launches SET document='{}'", "DELETE FROM scanner_launches"} {
		if _, e = q.S.DB.Exec(statement); e == nil {
			t.Fatal("launch mutation accepted")
		}
	}
	rows, e := q.Launches(l.Job.Owner, l.Job.ID)
	if e != nil || len(rows) != 1 || rows[0].Digest != got.Digest {
		t.Fatal(rows, e)
	}
	if _, e = q.Launches("owner-b", l.Job.ID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner attempt exposed", e)
	}
	p.Container = "aegis-scan-" + strings.Repeat("b", 32)
	if _, e = q.RegisterLaunch(l, p); !errors.Is(e, ErrConflict) {
		t.Fatal("retry changed immutable attempt", e)
	}
	p.Container = got.Document.Plan.Container
	later := q.now().Add(20 * time.Second)
	q.Now = func() time.Time { return later }
	if _, e = q.RegisterLaunch(l, p); !errors.Is(e, ErrLease) {
		t.Fatal("expired registration replay authorized a new start", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE document LIKE '%scanner.launch%'").Scan(&n)
	if n != 1 {
		t.Fatal("registration replay duplicated audit", n)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}

func TestNewReceiptMustMatchRecordedAttempt(t *testing.T) {
	for _, kind := range []string{"absent", "container", "snapshot", "version", "started", "preflight"} {
		t.Run(kind, func(t *testing.T) {
			q, l, r, p := launchFixture(t)
			if kind != "absent" {
				if _, e := q.RegisterLaunch(l, p); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "container":
				r.Container = "aegis-scan-" + strings.Repeat("b", 32)
			case "snapshot":
				r.Snapshot.Digest = domain.Hash([]byte("wrong"))
			case "version":
				r.Version = "wrong"
			case "started":
				r.Started = q.now().Add(time.Millisecond).Format(time.RFC3339Nano)
			case "preflight":
				r.Container = ""
				r.Status = "tool_error"
				r.Result.Status = "tool_error"
				r.Exit = -1
				r.DurationLimit = 0
				r.GuardDigest = ""
				r.Cleanup = "unconfirmed"
			}
			if _, e := q.RecordReceipt(l, r); e == nil {
				t.Fatal("unbound attempt accepted")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n)
			if n != 0 {
				t.Fatal("rejected receipt persisted")
			}
		})
	}
	q, l, r, p := launchFixture(t)
	if _, e := q.RegisterLaunch(l, p); e != nil {
		t.Fatal(e)
	}
	if _, e := q.RecordReceipt(l, r); e != nil {
		t.Fatal("bound receipt rejected", e)
	}
}

func TestLaunchRefusesAuthorityIdentityAndUnsafeReferences(t *testing.T) {
	for _, kind := range []string{"owner", "request", "capability", "cancelled", "revoked", "legacy", "tool", "container", "engine", "workspace", "registry", "snapshot", "pins"} {
		t.Run(kind, func(t *testing.T) {
			q, l, _, p := launchFixture(t)
			switch kind {
			case "owner":
				l.Job.Owner = "owner-b"
			case "request":
				l.Job.RequestDigest = domain.Hash([]byte("wrong"))
			case "capability":
				l.Token = strings.Repeat("f", 64)
			case "cancelled":
				if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
					t.Fatal(e)
				}
			case "revoked":
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=?", l.Worker)
			case "legacy":
				q.S.DB.Exec("UPDATE scanner_dispatch SET launch_protocol=0")
			case "tool":
				p.Tool = "semgrep_ce"
			case "container":
				p.Container = "unrelated-container"
			case "engine":
				p.Engine = "tcp://127.0.0.1:2375"
			case "workspace":
				p.Workspace = "../../private"
			case "registry":
				p.Registry = "/tmp/registry"
			case "snapshot":
				p.Snapshot = domain.Hash([]byte("wrong"))
			case "pins":
				q.LockDigest = domain.Hash([]byte("changed pins"))
			}
			if _, e := q.RegisterLaunch(l, p); e == nil {
				t.Fatal("unsafe registration accepted")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
			if n != 0 {
				t.Fatal("refusal persisted attempt")
			}
		})
	}
}

func TestLaunchAuditFailureRollsBackWithoutFreeingAdmission(t *testing.T) {
	q, l, _, p := launchFixture(t)
	if _, e := q.S.DB.Exec("CREATE TRIGGER refuse_launch_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := q.RegisterLaunch(l, p); e == nil {
		t.Fatal("unaudited launch committed")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
	if n != 0 {
		t.Fatal("launch not rolled back")
	}
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 1 {
		t.Fatal("failure released admission")
	}
}

func TestSuiteLaunchesCannotSwitchExecutionEngineOrRegistry(t *testing.T) {
	for _, kind := range []string{"engine", "registry"} {
		t.Run(kind, func(t *testing.T) {
			q, l, r, _ := receiptFixture(t, "bandit", "gitleaks")
			q.Pins["gitleaks"] = Pin{Version: "8.30.1", Image: domain.Hash([]byte("gitleaks image"))}
			p := scanevidence.LaunchPlan{Guard: q.Guards.AMD64, Architecture: "amd64", Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: domain.Hash([]byte("engine")), Workspace: "run-" + strings.Repeat("a", 32), Registry: domain.Hash([]byte("registry")), Snapshot: r.Snapshot.Digest}
			reserveLaunchWorkspace(t, q, l, p)
			if _, e := q.RegisterLaunch(l, p); e != nil {
				t.Fatal(e)
			}
			p.Tool = "gitleaks"
			p.Container = "aegis-scan-" + strings.Repeat("b", 32)
			p.Workspace = "run-" + strings.Repeat("b", 32)
			if kind == "engine" {
				p.Engine = domain.Hash([]byte("another engine"))
			} else {
				p.Registry = domain.Hash([]byte("another registry"))
			}
			_, reserveErr := q.ReserveWorkspace(l, scanevidence.WorkspacePlan{Tool: p.Tool, Workspace: p.Workspace, Registry: p.Registry, Snapshot: p.Snapshot})
			if kind == "registry" {
				if !errors.Is(reserveErr, ErrConflict) {
					t.Fatal("suite switched reserved namespace", reserveErr)
				}
				return
			}
			if reserveErr != nil {
				t.Fatal(reserveErr)
			}
			if _, e := q.RegisterLaunch(l, p); !errors.Is(e, ErrConflict) {
				t.Fatal("suite changed original cleanup namespace", e)
			}
		})
	}
}

func TestLaunchCannotCommitAfterLeaseExpiresDuringPreparation(t *testing.T) {
	q, l, _, p := launchFixture(t)
	now := q.now()
	calls := 0
	q.Now = func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(20 * time.Second)
		}
		return now
	}
	if _, e := q.RegisterLaunch(l, p); !errors.Is(e, ErrLease) {
		t.Fatal("late preparation authorized execution", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
	if n != 0 {
		t.Fatal("expired preparation persisted attempt")
	}
}
