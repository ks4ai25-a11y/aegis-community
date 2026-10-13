package research

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scope"
	"aegis.local/controller/internal/store"
	"aegis.local/controller/internal/verify"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Queue, *time.Time, GrantRecord, Input) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	for _, id := range []string{"owner-a", "owner-b"} {
		if _, e = s.DB.Exec("INSERT INTO owners VALUES(?,'unused-fixture-hash',?)", id, domain.Now()); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC()
	q := &Queue{S: s, Now: func() time.Time { return now }}
	g, e := q.CreateGrant("owner-a", 10)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.Approve("owner-a", g.Grant.ID, g.Digest, true); e != nil {
		t.Fatal(e)
	}
	_, d, e := s.Active()
	if e != nil {
		t.Fatal(e)
	}
	in := Input{"1.0", "app_demo", g.Grant.ID, g.Digest, scope.Fixture, d}
	return q, &now, g, in
}
func proof(l Lease) domain.Report {
	baseline := l.Policy
	baseline.Mode = "observe"
	baseline.Parent = ""
	baseline.Exclusions = []domain.Exclusion{}
	baseline.Metadata = domain.Metadata{Rationale: "Fixed Observe baseline", RequestedBy: "fixture"}
	negativeStatus := 200
	if l.Policy.Mode == "protect" {
		negativeStatus = 403
	}
	r := domain.Report{Schema: "1.0", ID: domain.ID(), Job: l.Job.ID, ScopeGrant: l.Job.Scope, ScopeDigest: l.Input.ScopeDigest, Fixture: scope.Fixture, FixtureDigest: verify.FixtureDigest(), Baseline: domain.Digest(baseline), Candidate: l.Job.InputDigest, Overall: "PASS", Checks: []domain.Check{{ID: "control-allowed", Result: "PASS", BaselineStatus: 200, CandidateStatus: 200, Rules: []string{}}, {ID: "negative-matched-and-mode-correct", Result: "PASS", BaselineStatus: 200, CandidateStatus: negativeStatus, Rules: []string{"942100"}, BaselineRules: []string{"942100"}}}, Limitations: []string{"Synthetic queue unit proof only"}}
	r.Digest = domain.Digest(r)
	return r
}
func TestOwnerAndIdempotency(t *testing.T) {
	q, _, g, in := fixture(t)
	j, e := q.Enqueue("owner-a", "stable-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	again, e := q.Enqueue("owner-a", "stable-key-001", in)
	if e != nil || again.ID != j.ID {
		t.Fatal(again, e)
	}
	other := in
	other.ScopeDigest = "sha256:changed"
	if _, e = q.Enqueue("owner-a", "stable-key-001", other); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, e = q.Get("owner-b", j.ID); e != sql.ErrNoRows {
		t.Fatal("cross-owner job exposed", e)
	}
	if _, e = q.Grant("owner-b", g.Grant.ID); e != sql.ErrNoRows {
		t.Fatal("cross-owner grant exposed", e)
	}
	if _, e = q.Enqueue("owner-b", "stable-key-001", in); !errors.Is(e, ErrScope) {
		t.Fatal(e)
	}
}
func TestRevocationCancelsRunningAndSuppressesSuccess(t *testing.T) {
	q, _, g, in := fixture(t)
	j, e := q.Enqueue("owner-a", "revoke-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("fixture-worker")
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Revoke("owner-a", g.Grant.ID); e != nil {
		t.Fatal(e)
	}
	if e = q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("revoked worker renewed", e)
	}
	r := proof(l)
	if e = q.Finish(l, &r, ""); e != nil {
		t.Fatal(e)
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" || got.Report != "" {
		t.Fatal(got, e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM reports").Scan(&n)
	if n != 0 {
		t.Fatal("cancelled proof persisted")
	}
}
func TestLeaseExpiryNeverAcceptsStaleWorker(t *testing.T) {
	q, now, _, in := fixture(t)
	j, e := q.Enqueue("owner-a", "expiry-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("worker-before-crash")
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(16 * time.Second)
	if _, e = q.Claim("replacement-worker"); e != sql.ErrNoRows {
		t.Fatal(e)
	}
	r := proof(l)
	if e = q.Finish(l, &r, ""); !errors.Is(e, ErrLease) {
		t.Fatal("stale worker accepted", e)
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "timeout" {
		t.Fatal(got, e)
	}
}
func TestExpiredQueuedGrantCannotStart(t *testing.T) {
	q, now, _, in := fixture(t)
	j, e := q.Enqueue("owner-a", "queued-expiry-001", in)
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(11 * time.Minute)
	if _, e = q.Claim("worker"); e != sql.ErrNoRows {
		t.Fatal(e)
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" {
		t.Fatal(got, e)
	}
}
func TestCancellationCannotBecomeGreen(t *testing.T) {
	q, _, _, in := fixture(t)
	j, e := q.Enqueue("owner-a", "cancel-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("worker")
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Cancel("owner-a", j.ID); e != nil {
		t.Fatal(e)
	}
	r := proof(l)
	if e = q.Finish(l, &r, ""); e != nil {
		t.Fatal(e)
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" {
		t.Fatal(got, e)
	}
}
func TestReportIdentityAndSuccessfulJob(t *testing.T) {
	q, _, _, in := fixture(t)
	j, e := q.Enqueue("owner-a", "success-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("worker")
	if e != nil {
		t.Fatal(e)
	}
	r := proof(l)
	r.Candidate = "wrong-policy"
	if e = q.Finish(l, &r, ""); e == nil {
		t.Fatal("tampered proof accepted")
	}
	r = proof(l)
	if e = q.Finish(l, &r, ""); e != nil {
		t.Fatal(e)
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "success" || got.Report != r.Digest {
		t.Fatal(got, e)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}

func TestScopeTotalRequestBudgetCannotBeReused(t *testing.T) {
	q, _, g, in := fixture(t)
	if _, e := q.Enqueue("owner-a", "budget-key-001", in); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Claim("worker"); e != nil {
		t.Fatal(e)
	}
	grant, e := q.Grant("owner-a", g.Grant.ID)
	if e != nil || grant.RequestsRemaining != 0 {
		t.Fatal(grant, e)
	}
	if _, e = q.Enqueue("owner-a", "budget-key-002", in); !errors.Is(e, ErrScope) {
		t.Fatal("exhausted budget reused", e)
	}
}

func TestRunningWorkerInterruptsOnRevocation(t *testing.T) {
	q, _, g, in := fixture(t)
	j, e := q.Enqueue("owner-a", "interrupt-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("worker")
	if e != nil {
		t.Fatal(e)
	}
	started := make(chan struct{})
	finished := make(chan struct{})
	w := &Worker{Q: q, Run: func(ctx context.Context, l Lease) (domain.Report, error) {
		close(started)
		<-ctx.Done()
		return domain.Report{}, ctx.Err()
	}}
	go func() { w.execute(context.Background(), l); close(finished) }()
	<-started
	if e = q.Revoke("owner-a", g.Grant.ID); e != nil {
		t.Fatal(e)
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("running worker did not stop")
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" || got.Report != "" {
		t.Fatal(got, e)
	}
}
