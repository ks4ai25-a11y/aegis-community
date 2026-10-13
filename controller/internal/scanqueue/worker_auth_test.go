// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enrolled(t *testing.T, q *Queue, minutes int) (*scannerauth.Registry, scannerauth.Enrollment) {
	t.Helper()
	r := &scannerauth.Registry{S: q.S, Now: q.now}
	e, err := r.Enroll("owner-a", "enrolled-worker", minutes)
	if err != nil {
		t.Fatal(err)
	}
	return r, e
}
func TestWorkerEnrollmentHashPrivacyAndOwnership(t *testing.T) {
	q, _, _ := fixture(t)
	r, e := enrolled(t, q, 60)
	if len(e.Token) != 64 {
		t.Fatal("worker capability entropy missing")
	}
	w, err := r.Authenticate(e.Token)
	if err != nil || w.Owner != "owner-a" || w.ID != "enrolled-worker" {
		t.Fatal(w, err)
	}
	var hash string
	if err = q.S.DB.QueryRow("SELECT token_hash FROM scanner_workers WHERE id=?", w.ID).Scan(&hash); err != nil || hash != domain.Hash([]byte(e.Token)) || hash == e.Token {
		t.Fatal("plaintext worker credential persisted", err)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), e.Token) {
		t.Fatal("worker credential serialized")
	}
	rows, err := q.S.DB.Query("SELECT document FROM audit")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		rows.Scan(&raw)
		if strings.Contains(raw, e.Token) {
			t.Fatal("worker credential leaked in audit")
		}
	}
}
func TestWorkerRoleCannotTransferOrUseOwnerAuthority(t *testing.T) {
	q, in, _ := fixture(t)
	r, e := enrolled(t, q, 60)
	if _, err := r.Enroll("owner-b", "stolen-worker", 60); !errors.Is(err, scannerauth.ErrDenied) {
		t.Fatal("foreign mount enrollment accepted", err)
	}
	if _, err := r.Authenticate("owner-session-cookie"); !errors.Is(err, scannerauth.ErrDenied) {
		t.Fatal("owner session became worker role", err)
	}
	if _, err := q.Enqueue("owner-a", "worker-owner-key", in); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Claim("enrolled-worker", "owner-b"); !errors.Is(err, ErrLease) {
		t.Fatal("worker claimed foreign owner", err)
	}
	if _, err := q.Claim("unregistered-worker", "owner-a"); !errors.Is(err, ErrLease) {
		t.Fatal("unregistered worker claimed", err)
	}
	if err := r.Revoke("owner-b", e.Worker.ID); err != sql.ErrNoRows {
		t.Fatal("foreign owner revoked worker", err)
	}
	if _, err := q.Claim(e.Worker.ID, e.Worker.Owner); err != nil {
		t.Fatal(err)
	}
}
func TestWorkerRevocationClosesAuthenticationClaimAndRenewal(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	r, e := enrolled(t, q, 60)
	if _, err := q.Enqueue("owner-a", "worker-revoke-key", in); err != nil {
		t.Fatal(err)
	}
	l, err := q.Claim(e.Worker.ID, e.Worker.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Revoke("owner-a", e.Worker.ID); err != nil {
		t.Fatal(err)
	}
	if err = r.Revoke("owner-a", e.Worker.ID); err != nil {
		t.Fatal("revocation not idempotent", err)
	}
	if _, err = r.Authenticate(e.Token); !errors.Is(err, scannerauth.ErrDenied) {
		t.Fatal("revoked worker authenticated", err)
	}
	if err = q.Guard(l); !errors.Is(err, ErrLease) {
		t.Fatal("revoked lease renewed", err)
	}
	got, err := q.Get("owner-a", l.Job.ID)
	if err != nil || !got.CancelRequested || got.State != "running" {
		t.Fatal("revocation implied container already stopped", got, err)
	}
	*now = now.Add(16 * time.Second)
	if err = q.Reconcile(); err != nil {
		t.Fatal(err)
	}
	got, err = q.Get("owner-a", l.Job.ID)
	if err != nil || got.State != "cancelled" || got.Error != "WORKER_REVOKED" {
		t.Fatal("worker revocation cause lost", got, err)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal("revocation released uncertain admission")
	}
}
func TestWorkerAuthenticationThenRevocationCannotRaceClaim(t *testing.T) {
	q, in, _ := fixture(t)
	r, e := enrolled(t, q, 60)
	w, err := r.Authenticate(e.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Enqueue("owner-a", "revoke-before-claim-key", in); err != nil {
		t.Fatal(err)
	}
	if err = r.Revoke("owner-a", e.Worker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Claim(w.ID, w.Owner); !errors.Is(err, ErrLease) {
		t.Fatal("stale transport authentication authorized claim", err)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 0 {
		t.Fatal("revocation race acquired admission")
	}
}
func TestWorkerExpiryCannotExtendOtherwiseLiveLease(t *testing.T) {
	q, in, _ := fixture(t)
	now := clock(q)
	r, e := enrolled(t, q, 1)
	if _, err := q.Enqueue("owner-a", "worker-expiry-key", in); err != nil {
		t.Fatal(err)
	}
	l, err := q.Claim(e.Worker.ID, e.Worker.Owner)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		*now = now.Add(10 * time.Second)
		if err = q.Guard(l); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(9 * time.Second)
	if err = q.Guard(l); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	if _, err = r.Authenticate(e.Token); !errors.Is(err, scannerauth.ErrDenied) {
		t.Fatal("expired worker authenticated", err)
	}
	if err = q.Guard(l); !errors.Is(err, ErrLease) {
		t.Fatal("worker expiry extended live job lease", err)
	}
}
func TestWorkerEnrollmentAndRevocationAuditFailureRollback(t *testing.T) {
	q, in, _ := fixture(t)
	r := &scannerauth.Registry{S: q.S, Now: q.now}
	on := func() {
		t.Helper()
		if _, err := q.S.DB.Exec("CREATE TRIGGER refuse_worker_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END"); err != nil {
			t.Fatal(err)
		}
	}
	off := func() {
		t.Helper()
		if _, err := q.S.DB.Exec("DROP TRIGGER refuse_worker_audit"); err != nil {
			t.Fatal(err)
		}
	}
	on()
	if _, err := r.Enroll("owner-a", "atomic-worker", 60); err == nil {
		t.Fatal("worker enrolled without audit")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_workers WHERE id='atomic-worker'").Scan(&n)
	if n != 0 {
		t.Fatal("failed enrollment retained role")
	}
	off()
	e, err := r.Enroll("owner-a", "atomic-worker", 60)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Enqueue("owner-a", "atomic-worker-job-key", in); err != nil {
		t.Fatal(err)
	}
	l, err := q.Claim(e.Worker.ID, e.Worker.Owner)
	if err != nil {
		t.Fatal(err)
	}
	on()
	if err = r.Revoke("owner-a", e.Worker.ID); err == nil {
		t.Fatal("worker revoked without audit")
	}
	if _, err = r.Authenticate(e.Token); err != nil {
		t.Fatal("failed revocation changed role", err)
	}
	got, err := q.Get("owner-a", l.Job.ID)
	if err != nil || got.CancelRequested {
		t.Fatal("failed revocation changed authority", got, err)
	}
	off()
	if err = q.S.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
}
func TestWorkerEnrollmentBudgetsAndNoSilentRotation(t *testing.T) {
	q, _, _ := fixture(t)
	r, e := enrolled(t, q, 60)
	if _, err := r.Enroll("owner-a", e.Worker.ID, 60); !errors.Is(err, scannerauth.ErrConflict) {
		t.Fatal("worker identity silently rotated", err)
	}
	for _, minutes := range []int{0, 1441} {
		if _, err := r.Enroll("owner-a", "invalid-time-worker", minutes); !errors.Is(err, scannerauth.ErrInput) {
			t.Fatal("unbounded lifetime accepted", err)
		}
	}
	for _, id := range []string{"more-worker-a", "more-worker-b", "more-worker-c"} {
		if _, err := r.Enroll("owner-a", id, 60); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Enroll("owner-a", "over-budget-worker", 60); !errors.Is(err, scannerauth.ErrConflict) {
		t.Fatal("active worker budget exceeded", err)
	}
	if err := r.Revoke("owner-a", e.Worker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enroll("owner-a", e.Worker.ID, 60); !errors.Is(err, scannerauth.ErrConflict) {
		t.Fatal("revoked identity silently reused", err)
	}
}

func TestWorkerCredentialFileIsPrivateExclusiveAndAuditBound(t *testing.T) {
	q, _, _ := fixture(t)
	r := &scannerauth.Registry{S: q.S, Now: q.now}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "worker-token")
	w, err := r.EnrollFile("owner-a", "file-worker", 60, path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != 65 {
		t.Fatal("credential delivery failed", err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("credential permissions", err)
	}
	got, err := r.Authenticate(strings.TrimSpace(string(raw)))
	if err != nil || got.ID != w.ID {
		t.Fatal("delivered credential does not authenticate", err)
	}
	if _, err = r.EnrollFile("owner-a", "replacement-worker", 60, path); !errors.Is(err, scannerauth.ErrCredential) {
		t.Fatal("existing credential overwritten", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(raw) {
		t.Fatal("existing credential changed", err)
	}
	link := filepath.Join(parent, "credential-link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = r.EnrollFile("owner-a", "symlink-worker", 60, link); !errors.Is(err, scannerauth.ErrCredential) {
		t.Fatal("credential symlink accepted", err)
	}
	failed := filepath.Join(parent, "failed-token")
	if _, err = q.S.DB.Exec("CREATE TRIGGER refuse_delivery_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.EnrollFile("owner-a", "failed-file-worker", 60, failed); err == nil {
		t.Fatal("credential role committed without audit")
	}
	if _, err = os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("failed issuance file retained", err)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_workers WHERE id IN ('replacement-worker','symlink-worker','failed-file-worker')").Scan(&n)
	if n != 0 {
		t.Fatal("failed credential delivery retained new roles", n)
	}
}
func TestWorkerRetainedEnrollmentBudget(t *testing.T) {
	q, _, _ := fixture(t)
	r := &scannerauth.Registry{S: q.S, Now: q.now}
	_, err := q.S.DB.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<96)
 INSERT INTO scanner_workers SELECT 'retained-worker-'||i,'owner-a','retained-hash-'||i,'revoked',0,'2026-10-13T00:00:00Z' FROM n`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Enroll("owner-a", "retention-overflow-worker", 60); !errors.Is(err, scannerauth.ErrConflict) {
		t.Fatal("unbounded worker history", err)
	}
}
