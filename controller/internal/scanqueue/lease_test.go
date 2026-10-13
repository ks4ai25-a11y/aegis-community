// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func clock(q *Queue) *time.Time { now := q.now(); q.Now = func() time.Time { return now }; return &now }
func enqueueClaim(t *testing.T, q *Queue, in Input) Lease {
	t.Helper()
	if _, e := q.Enqueue("owner-a", "lease-test-key", in); e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("trusted-worker", "owner-a")
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func TestLeaseClaimBindsMapAndSerializesAdmission(t *testing.T) {
	q, in, _ := fixture(t)
	l := enqueueClaim(t, q, in)
	if l.Job.State != "running" || l.Map.Digest != in.MapDigest || l.Map.SourceRef != "mounted-asset:fixture" || len(l.Token) != 64 {
		t.Fatal(l.Job)
	}
	if got := l.Deadline.Sub(q.now()); got != 310*time.Second {
		t.Fatal("unexpected bounded suite deadline", got)
	}
	if _, e := q.Claim("another-worker", "owner-a"); !errors.Is(e, ErrCleanup) {
		t.Fatal("concurrent admission accepted", e)
	}
	if e := q.Guard(l); e != nil {
		t.Fatal(e)
	}
	var hash, raw string
	q.S.DB.QueryRow("SELECT token_hash FROM scanner_dispatch").Scan(&hash)
	if hash == l.Token || hash != domain.Hash([]byte(l.Token)) {
		t.Fatal("lease capability stored in plaintext")
	}
	rows, e := q.S.DB.Query("SELECT document FROM audit")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&raw)
		if strings.Contains(raw, l.Token) {
			t.Fatal("lease capability in audit")
		}
	}
	b, _ := json.Marshal(l)
	if strings.Contains(string(b), l.Token) {
		t.Fatal("lease capability serialized by general JSON")
	}
}
func TestLeaseRenewalCannotReviveOrExceedDeadline(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	in.Tools = []string{"bandit"}
	in.Duration = 1
	l := enqueueClaim(t, q, in)
	for i := 0; i < 6; i++ {
		*now = now.Add(10 * time.Second)
		if e := q.Guard(l); e != nil {
			t.Fatal(e)
		}
	}
	var until int64
	q.S.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&until)
	if until != l.Deadline.Unix() {
		t.Fatal("renewal exceeded immutable deadline", until, l.Deadline)
	}
	*now = l.Deadline
	if e := q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("deadline renewed", e)
	}
	if e := q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	j, e := q.Get("owner-a", l.Job.ID)
	if e != nil || j.State != "timeout" || j.Error != "JOB_DEADLINE_EXCEEDED" {
		t.Fatal(j, e)
	}
}
func TestCancelledRunningLeaseNeverAcceptsSuccessOrReleasesSlot(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	l := enqueueClaim(t, q, in)
	if e := q.Cancel("owner-a", l.Job.ID); e != nil {
		t.Fatal(e)
	}
	if e := q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("cancelled lease renewed", e)
	}
	if e := q.Fail(l, "SCANNER_EXECUTION_FAILED"); !errors.Is(e, ErrLease) {
		t.Fatal("late worker overrode cancellation", e)
	}
	*now = now.Add(16 * time.Second)
	if e := q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	j, e := q.Get("owner-a", l.Job.ID)
	if e != nil || j.State != "cancelled" {
		t.Fatal(j, e)
	}
	if _, e = q.Claim("trusted-worker", "owner-a"); !errors.Is(e, ErrCleanup) {
		t.Fatal("cancellation implied external cleanup", e)
	}
}
func TestCrashRecoveryRetainsUncertainDispatchAfterRestart(t *testing.T) {
	q, in, path := fixture(t)
	now := clock(q)
	l := enqueueClaim(t, q, in)
	if _, e := q.Enqueue("owner-a", "successor-job-key", in); e != nil {
		t.Fatal(e)
	}
	if e := q.S.DB.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	q.S = s
	*now = now.Add(16 * time.Second)
	if _, e = q.Claim("successor-worker", "owner-a"); !errors.Is(e, ErrCleanup) {
		t.Fatal("uncertain prior execution automatically repeated", e)
	}
	j, e := q.Get("owner-a", l.Job.ID)
	if e != nil || j.State != "timeout" || j.Error != "WORKER_LEASE_EXPIRED" {
		t.Fatal(j, e)
	}
	var state string
	s.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal(state)
	}
	if e = q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("expired lease revived", e)
	}
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestQueuedExpiryDoesNotAcquireOrExecute(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	j, e := q.Enqueue("owner-a", "expired-job-key", in)
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(15 * time.Minute)
	if _, e = q.Claim("trusted-worker", "owner-a"); e != sql.ErrNoRows {
		t.Fatal(e)
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "timeout" || got.Error != "QUEUE_EXPIRED" {
		t.Fatal(got, e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 0 {
		t.Fatal("expired job acquired external admission")
	}
}
func TestChangedSourceOrPinsRefusedBeforeClaim(t *testing.T) {
	for _, change := range []string{"map", "lock", "map-document"} {
		t.Run(change, func(t *testing.T) {
			q, in, _ := fixture(t)
			j, e := q.Enqueue("owner-a", "changed-claim-key", in)
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "map":
				_, e = q.S.DB.Exec("UPDATE repositories SET map_digest=? WHERE id=?", domain.Hash([]byte("changed")), in.Repository)
			case "lock":
				q.LockDigest = domain.Hash([]byte("changed"))
			case "map-document":
				_, e = q.S.DB.Exec("UPDATE application_maps SET document='{}' WHERE repository=?", in.Repository)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = q.Claim("trusted-worker", "owner-a"); !errors.Is(e, ErrConflict) {
				t.Fatal("changed authority accepted", e)
			}
			got, e := q.Get("owner-a", j.ID)
			if e != nil || got.State != "tool_error" || got.Error != "SCAN_IDENTITY_CHANGED" {
				t.Fatal(got, e)
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
			if n != 0 {
				t.Fatal("invalid source/pins admitted")
			}
		})
	}
}
func TestWorkerAndCapabilityForgeryRefused(t *testing.T) {
	q, in, _ := fixture(t)
	l := enqueueClaim(t, q, in)
	for _, change := range []string{"worker", "token", "request", "job"} {
		bad := l
		switch change {
		case "worker":
			bad.Worker = "other-worker"
		case "token":
			bad.Token = strings.Repeat("0", 64)
		case "request":
			bad.Job.RequestDigest = domain.Hash([]byte("other request"))
		case "job":
			bad.Job.ID = "other-job"
		}
		if e := q.Guard(bad); !errors.Is(e, ErrLease) {
			t.Fatal(change, e)
		}
	}
	if e := q.Guard(l); e != nil {
		t.Fatal("valid lease disturbed", e)
	}
}
func TestClaimAndRecoveryAuditFailureRollback(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	j, e := q.Enqueue("owner-a", "claim-audit-key", in)
	if e != nil {
		t.Fatal(e)
	}
	on := func() {
		t.Helper()
		if _, e := q.S.DB.Exec("CREATE TRIGGER refuse_lease_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END"); e != nil {
			t.Fatal(e)
		}
	}
	off := func() {
		t.Helper()
		if _, e := q.S.DB.Exec("DROP TRIGGER refuse_lease_audit"); e != nil {
			t.Fatal(e)
		}
	}
	on()
	if _, e = q.Claim("trusted-worker", "owner-a"); e == nil {
		t.Fatal("claim succeeded without audit")
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "queued" {
		t.Fatal(got, e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 0 {
		t.Fatal("rolled-back admission survived")
	}
	off()
	l, e := q.Claim("trusted-worker", "owner-a")
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(16 * time.Second)
	on()
	if e = q.Reconcile(); e == nil {
		t.Fatal("recovery succeeded without audit")
	}
	got, e = q.Get("owner-a", j.ID)
	if e != nil || got.State != "running" {
		t.Fatal(got, e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "active" {
		t.Fatal("recovery was not atomic", state)
	}
	if e = q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("audit failure revived expired authority", e)
	}
	off()
	if e = q.Reconcile(); e != nil {
		t.Fatal(e)
	}
}
func TestToolFailureKeepsCleanupAdmissionClosed(t *testing.T) {
	q, in, _ := fixture(t)
	l := enqueueClaim(t, q, in)
	if e := q.Fail(l, "raw source or arbitrary stderr"); !errors.Is(e, ErrInput) {
		t.Fatal("raw failure persisted", e)
	}
	if e := q.Fail(l, "SOURCE_CAPTURE_FAILED"); e != nil {
		t.Fatal(e)
	}
	got, e := q.Get("owner-a", l.Job.ID)
	if e != nil || got.State != "tool_error" {
		t.Fatal(got, e)
	}
	if _, e = q.Claim("other-worker", "owner-a"); !errors.Is(e, ErrCleanup) {
		t.Fatal("tool error implied cleanup", e)
	}
}
func TestConcurrentWorkersClaimOnlyOnce(t *testing.T) {
	q, in, _ := fixture(t)
	if _, e := q.Enqueue("owner-a", "concurrent-claim-key", in); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := q.Claim("trusted-worker", "owner-a"); errs <- e }()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		} else if !errors.Is(e, ErrCleanup) {
			t.Fatal(e)
		}
	}
	if successes != 1 {
		t.Fatal("multiple worker claims", successes)
	}
}

func TestFailureFinishIsIdempotentAndAuditedAtomically(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	l := enqueueClaim(t, q, in)
	if _, e := q.S.DB.Exec("CREATE TRIGGER refuse_finish_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END"); e != nil {
		t.Fatal(e)
	}
	if e := q.Fail(l, "TOOL_UNAVAILABLE"); e == nil {
		t.Fatal("failure persisted without audit")
	}
	got, e := q.Get("owner-a", l.Job.ID)
	if e != nil || got.State != "running" {
		t.Fatal("failed finish changed job", got, e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "active" {
		t.Fatal("failed finish changed admission", state)
	}
	if _, e = q.S.DB.Exec("DROP TRIGGER refuse_finish_audit"); e != nil {
		t.Fatal(e)
	}
	if e = q.Fail(l, "TOOL_UNAVAILABLE"); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Hour)
	if e = q.Fail(l, "TOOL_UNAVAILABLE"); e != nil {
		t.Fatal("exact terminal replay not idempotent", e)
	}
	if e = q.Fail(l, "SCANNER_EXECUTION_FAILED"); !errors.Is(e, ErrConflict) {
		t.Fatal("terminal replay rewrote failure", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE json_extract(document,'$.action')='scanner.finished'").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate terminal audit", n)
	}
}
