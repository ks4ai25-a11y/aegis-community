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

func completedReceipt(t *testing.T, status string) (*Queue, Lease, scanevidence.Execution, string) {
	q, l, r, path := receiptFixture(t, "bandit")
	r.Status = status
	r.Result.Status = status
	r.Exit = 0
	r.Container = "aegis-scan-" + strings.Repeat("a", 32)
	r.GuardDigest = domain.Hash([]byte("guard"))
	r.DurationLimit = l.Job.Input.Duration
	r.Cleanup = "complete"
	if status == "completed_partial" {
		r.Result.Diagnostics = []scanevidence.Diagnostic{{Code: "SCAN_PARTIAL", Message: "arbitrary original diagnostic"}}
	}
	return q, l, r, path
}

func TestFinalizeDerivesTerminalResultAndImmutableRestartReplay(t *testing.T) {
	q, l, r, path := completedReceipt(t, "completed")
	receipt, e := q.RecordReceipt(l, r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := q.Finalize(l)
	if e != nil {
		t.Fatal(e)
	}
	if got.Document.Status != "completed" || got.Document.Tier != "T0" || !got.Document.CleanupRequired || got.Document.Tools[0].Receipt != receipt.Digest {
		t.Fatal(got)
	}
	j, e := q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || j.State != "completed" || j.Finished != got.Document.Created {
		t.Fatal(j, e)
	}
	if e = q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("terminal result renewed execution", e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal("result released cleanup", state)
	}
	if _, e = q.Result("owner-b", j.ID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner result exposed", e)
	}
	for _, statement := range []string{"UPDATE scanner_results SET document='{}'", "DELETE FROM scanner_results"} {
		if _, e = q.S.DB.Exec(statement); e == nil {
			t.Fatal("result mutation accepted")
		}
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	q.S.DB.Close()
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	later := q.now().Add(time.Minute)
	reopened := &Queue{S: s, LockDigest: domain.Hash([]byte("rotated pins")), Now: func() time.Time { return later }}
	replay, e := reopened.Finalize(l)
	if e != nil || replay.Digest != got.Digest {
		t.Fatal("result replay lost after restart/expiry", e)
	}
	read, e := reopened.Result(j.Owner, j.ID)
	if e != nil || read.Digest != got.Digest {
		t.Fatal("owner read lost result", e)
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE document LIKE '%scanner.finished%'").Scan(&n)
	if n != 1 {
		t.Fatal("replay duplicated terminal audit", n)
	}
}

func TestFinalizeKeepsPartialAndErrorStatus(t *testing.T) {
	for _, status := range []string{"completed_partial", "tool_error"} {
		t.Run(status, func(t *testing.T) {
			q, l, r, _ := completedReceipt(t, status)
			if status == "tool_error" {
				r.Exit = -1
				r.Container = ""
				r.GuardDigest = ""
				r.DurationLimit = 0
				r.Cleanup = "unconfirmed"
			}
			if _, e := q.RecordReceipt(l, r); e != nil {
				t.Fatal(e)
			}
			got, e := q.Finalize(l)
			if e != nil || got.Document.Status != status || got.Document.Partial != (status == "completed_partial") || got.Document.ToolError != (status == "tool_error") {
				t.Fatal(got, e)
			}
		})
	}
}

func TestFinalizeRefusesPartiallyReceivedRequestedSuite(t *testing.T) {
	q, l, r, _ := receiptFixture(t)
	if _, e := q.RecordReceipt(l, r); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Finalize(l); !errors.Is(e, ErrConflict) {
		t.Fatal("missing requested scanner became empty coverage", e)
	}
	j, e := q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || j.State != "running" {
		t.Fatal(j, e)
	}
}

func TestFinalizeRefusesMissingReceiptsAndWithdrawnAuthority(t *testing.T) {
	for _, kind := range []string{"missing", "owner", "request", "capability", "expired", "cancelled", "revoked", "map", "lock"} {
		t.Run(kind, func(t *testing.T) {
			q, l, r, _ := completedReceipt(t, "completed")
			if kind != "missing" {
				if _, e := q.RecordReceipt(l, r); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "owner":
				l.Job.Owner = "owner-b"
			case "request":
				l.Job.RequestDigest = domain.Hash([]byte("wrong"))
			case "capability":
				l.Token = strings.Repeat("f", 64)
			case "expired":
				now := q.now().Add(20 * time.Second)
				q.Now = func() time.Time { return now }
			case "cancelled":
				if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
					t.Fatal(e)
				}
			case "revoked":
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=?", l.Worker)
			case "map":
				q.S.DB.Exec("UPDATE repositories SET map_digest=? WHERE id=?", domain.Hash([]byte("changed")), l.Job.Input.Repository)
			case "lock":
				q.LockDigest = domain.Hash([]byte("changed pins"))
			}
			if _, e := q.Finalize(l); e == nil {
				t.Fatal("invalid finalization accepted")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_results").Scan(&n)
			if n != 0 {
				t.Fatal("refusal stored result")
			}
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
			if n != 1 {
				t.Fatal("refusal released admission")
			}
		})
	}
}

func TestFinalizeAuditFailureRollsBackResultJobAndDispatch(t *testing.T) {
	q, l, r, _ := completedReceipt(t, "completed")
	if _, e := q.RecordReceipt(l, r); e != nil {
		t.Fatal(e)
	}
	if _, e := q.S.DB.Exec("CREATE TRIGGER reject_finish_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Finalize(l); e == nil {
		t.Fatal("unaudited finalization committed")
	}
	j, e := q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || j.State != "running" || j.Finished != "" {
		t.Fatal(j, e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_results").Scan(&n)
	if n != 0 {
		t.Fatal("result not rolled back")
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "active" {
		t.Fatal("dispatch not rolled back", state)
	}
}

func TestResultDetectsAlteredIndexAndReceipt(t *testing.T) {
	for _, table := range []string{"scanner_results", "scanner_receipts"} {
		t.Run(table, func(t *testing.T) {
			q, l, r, _ := completedReceipt(t, "completed")
			if _, e := q.RecordReceipt(l, r); e != nil {
				t.Fatal(e)
			}
			if _, e := q.Finalize(l); e != nil {
				t.Fatal(e)
			}
			q.S.DB.Exec("DROP TRIGGER " + table + "_no_update")
			q.S.DB.Exec("UPDATE " + table + " SET document='{}'")
			if _, e := q.Result(l.Job.Owner, l.Job.ID); !errors.Is(e, ErrConflict) {
				t.Fatal("altered host data accepted", e)
			}
		})
	}
}

func TestFinalizeReplayCannotUseAnotherCapabilityOrRevokedRole(t *testing.T) {
	for _, kind := range []string{"capability", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			q, l, r, _ := completedReceipt(t, "completed")
			if _, e := q.RecordReceipt(l, r); e != nil {
				t.Fatal(e)
			}
			if _, e := q.Finalize(l); e != nil {
				t.Fatal(e)
			}
			if kind == "capability" {
				l.Token = strings.Repeat("f", 64)
			} else {
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=?", l.Worker)
			}
			if _, e := q.Finalize(l); !errors.Is(e, ErrLease) {
				t.Fatal("terminal replay bypassed original authority", e)
			}
		})
	}
}

func TestFinalizeRefusesFinishTimestampBeforeAcceptedReceipts(t *testing.T) {
	q, l, r, _ := completedReceipt(t, "completed")
	if _, e := q.RecordReceipt(l, r); e != nil {
		t.Fatal(e)
	}
	backward := q.now().Add(-500 * time.Millisecond)
	q.Now = func() time.Time { return backward }
	if _, e := q.Finalize(l); !errors.Is(e, ErrConflict) {
		t.Fatal("clock rollback backdated terminal evidence", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_results").Scan(&n)
	if n != 0 {
		t.Fatal("backdated result committed")
	}
}
