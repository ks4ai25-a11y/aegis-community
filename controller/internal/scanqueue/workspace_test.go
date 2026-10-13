// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func workspaceFixture(t *testing.T) (*Queue, Lease, scanevidence.WorkspacePlan, string) {
	t.Helper()
	q, l, r, path := receiptFixture(t, "bandit", "gitleaks")
	return q, l, scanevidence.WorkspacePlan{Tool: "bandit", Workspace: "run-" + strings.Repeat("a", 32), Registry: domain.Hash([]byte("registry")), Snapshot: r.Snapshot.Digest}, path
}
func TestWorkspaceReservationIsImmutableAuditedAndSurvivesCaptureCrash(t *testing.T) {
	q, l, p, path := workspaceFixture(t)
	got, e := q.ReserveWorkspace(l, p)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := q.ReserveWorkspace(l, p)
	if e != nil || replay.Digest != got.Digest {
		t.Fatal("live reservation replay", e)
	}
	for _, s := range []string{"UPDATE scanner_workspaces SET document='{}'", "DELETE FROM scanner_workspaces"} {
		if _, e = q.S.DB.Exec(s); e == nil {
			t.Fatal("reservation mutated")
		}
	}
	if _, e = q.Workspaces("owner-b", l.Job.ID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner reservation exposed", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE document LIKE '%scanner.workspace%'").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate reservation audit")
	}
	q.S.DB.Close()
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	later := q.now().Add(20 * time.Second)
	reopened := &Queue{S: s, LockDigest: q.LockDigest, Now: func() time.Time { return later }}
	if e = reopened.Reconcile(); e != nil {
		t.Fatal(e)
	}
	rows, e := reopened.Workspaces(l.Job.Owner, l.Job.ID)
	if e != nil || len(rows) != 1 || rows[0].Digest != got.Digest {
		t.Fatal("capture crash lost known reservation", e)
	}
	if _, e = reopened.ReserveWorkspace(l, p); !errors.Is(e, ErrLease) {
		t.Fatal("expired replay authorized allocation", e)
	}
	var state string
	s.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal("capture uncertainty released admission")
	}
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestWorkspaceReservationRejectsUnsafeAndWithdrawnAuthority(t *testing.T) {
	for _, kind := range []string{"owner", "request", "token", "tool", "workspace", "registry", "snapshot", "expiry", "cancelled", "revoked", "legacy", "map", "lock"} {
		t.Run(kind, func(t *testing.T) {
			q, l, p, _ := workspaceFixture(t)
			switch kind {
			case "owner":
				l.Job.Owner = "owner-b"
			case "request":
				l.Job.RequestDigest = domain.Hash([]byte("wrong"))
			case "token":
				l.Token = strings.Repeat("f", 64)
			case "tool":
				p.Tool = "syft"
			case "workspace":
				p.Workspace = "../../private"
			case "registry":
				p.Registry = "/private/tmp"
			case "snapshot":
				p.Snapshot = domain.Hash([]byte("wrong"))
			case "expiry":
				now := q.now().Add(20 * time.Second)
				q.Now = func() time.Time { return now }
			case "cancelled":
				if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
					t.Fatal(e)
				}
			case "revoked":
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=?", l.Worker)
			case "legacy":
				q.S.DB.Exec("UPDATE scanner_dispatch SET workspace_protocol=0")
			case "map":
				q.S.DB.Exec("UPDATE repositories SET map_digest='wrong'")
			case "lock":
				q.LockDigest = domain.Hash([]byte("wrong"))
			}
			if _, e := q.ReserveWorkspace(l, p); e == nil {
				t.Fatal("unsafe reservation accepted")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n)
			if n != 0 {
				t.Fatal("refusal persisted reservation")
			}
		})
	}
}
func TestWorkspaceReservationConflictsAndAuditRollback(t *testing.T) {
	q, l, p, _ := workspaceFixture(t)
	if _, e := q.ReserveWorkspace(l, p); e != nil {
		t.Fatal(e)
	}
	changed := p
	changed.Workspace = "run-" + strings.Repeat("b", 32)
	if _, e := q.ReserveWorkspace(l, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("reservation replaced", e)
	}
	changed = p
	changed.Tool = "gitleaks"
	if _, e := q.ReserveWorkspace(l, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("workspace identity reused", e)
	}
	changed.Workspace = "run-" + strings.Repeat("b", 32)
	changed.Registry = domain.Hash([]byte("different namespace"))
	if _, e := q.ReserveWorkspace(l, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("namespace switched", e)
	}
	q, l, p, _ = workspaceFixture(t)
	q.S.DB.Exec("CREATE TRIGGER refuse_workspace_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private SQL failure'); END")
	if _, e := q.ReserveWorkspace(l, p); e == nil {
		t.Fatal("unaudited reservation committed")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n)
	if n != 0 {
		t.Fatal("audit rollback lost")
	}
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 1 {
		t.Fatal("failure freed admission")
	}
}
func TestLaunchRequiresExactEarlierWorkspaceReservation(t *testing.T) {
	for _, kind := range []string{"absent", "workspace", "registry", "snapshot", "clock"} {
		t.Run(kind, func(t *testing.T) {
			q, l, r, _ := receiptFixture(t, "bandit")
			p := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: domain.Hash([]byte("engine")), Workspace: "run-" + strings.Repeat("a", 32), Registry: domain.Hash([]byte("registry")), Snapshot: r.Snapshot.Digest}
			if kind != "absent" {
				reserveLaunchWorkspace(t, q, l, p)
			}
			switch kind {
			case "workspace":
				p.Workspace = "run-" + strings.Repeat("b", 32)
			case "registry":
				p.Registry = domain.Hash([]byte("wrong"))
			case "snapshot":
				p.Snapshot = domain.Hash([]byte("wrong"))
			case "clock":
				now := q.now().Add(-time.Millisecond)
				q.Now = func() time.Time { return now }
			}
			if _, e := q.RegisterLaunch(l, p); e == nil {
				t.Fatal("launch escaped its earlier reservation")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
			if n != 0 {
				t.Fatal("rejected launch stored")
			}
		})
	}
}

func TestWorkspaceReservationRejectsTamperingAndLateCommit(t *testing.T) {
	q, l, p, _ := workspaceFixture(t)
	if _, e := q.ReserveWorkspace(l, p); e != nil {
		t.Fatal(e)
	}
	q.S.DB.Exec("DROP TRIGGER scanner_workspaces_no_update")
	q.S.DB.Exec("UPDATE scanner_workspaces SET document='{}'")
	if _, e := q.Workspaces(l.Job.Owner, l.Job.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("tampered reservation read", e)
	}
	if _, e := q.ReserveWorkspace(l, p); !errors.Is(e, ErrConflict) {
		t.Fatal("tampered reservation replay", e)
	}
	q, l, p, _ = workspaceFixture(t)
	now := q.now()
	calls := 0
	q.Now = func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(20 * time.Second)
		}
		return now
	}
	if _, e := q.ReserveWorkspace(l, p); !errors.Is(e, ErrLease) {
		t.Fatal("reservation committed after lease expired", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n)
	if n != 0 {
		t.Fatal("late reservation persisted")
	}
}

func TestLaunchStampCannotMoveBeforeReservedWorkspaceDuringPreparation(t *testing.T) {
	q, l, _, p := launchFixture(t)
	now := q.now()
	calls := 0
	q.Now = func() time.Time {
		calls++
		if calls >= 3 {
			return now.Add(-time.Millisecond)
		}
		return now
	}
	if _, e := q.RegisterLaunch(l, p); !errors.Is(e, ErrConflict) {
		t.Fatal("launch stamp moved before reservation", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
	if n != 0 {
		t.Fatal("chronologically invalid launch persisted")
	}
}
