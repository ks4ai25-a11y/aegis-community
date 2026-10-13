package research

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scope"
	"aegis.local/controller/internal/store"
	"aegis.local/controller/internal/verify"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

// Fail the actual SQLite audit insert, after earlier writes in the transaction.
// This models persistence failure without substituting a fake audit function.
func TestAuditFailureRollsBackResearchAuthorityAndEvidence(t *testing.T) {
	for _, operation := range []string{"draft", "approve", "enqueue", "claim", "cancel", "revoke", "finish", "recover"} {
		t.Run(operation, func(t *testing.T) {
			q, now, g, in := fixture(t)
			var draft GrantRecord
			var j Job
			var l Lease
			var e error
			if operation == "approve" {
				draft, e = q.CreateGrant("owner-a", 10)
			}
			if operation == "claim" || operation == "cancel" || operation == "revoke" || operation == "finish" || operation == "recover" {
				j, e = q.Enqueue("owner-a", "audit-failure-key", in)
			}
			if e != nil {
				t.Fatal(e)
			}
			if operation == "revoke" || operation == "finish" || operation == "recover" {
				l, e = q.Claim("test-worker")
				if e != nil {
					t.Fatal(e)
				}
			}
			if operation == "recover" {
				*now = now.Add(16 * time.Second)
			}
			before := researchState(t, q.S)
			if _, e = q.S.DB.Exec("CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'synthetic audit persistence failure'); END"); e != nil {
				t.Fatal(e)
			}
			switch operation {
			case "draft":
				_, e = q.CreateGrant("owner-a", 10)
			case "approve":
				_, e = q.Approve("owner-a", draft.Grant.ID, draft.Digest, true)
			case "enqueue":
				_, e = q.Enqueue("owner-a", "audit-failure-key", in)
			case "claim", "recover":
				_, e = q.Claim("test-worker")
			case "cancel":
				e = q.Cancel("owner-a", j.ID)
			case "revoke":
				e = q.Revoke("owner-a", g.Grant.ID)
			case "finish":
				r := proof(l)
				e = q.Finish(l, &r, "")
			}
			if e == nil {
				t.Fatal("audit failure ignored")
			}
			if after := researchState(t, q.S); after != before {
				t.Fatalf("unaudited state committed by %s", operation)
			}
			if e = q.S.VerifyAudit(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func researchState(t *testing.T, s *store.Store) string {
	t.Helper()
	out := [][][]any{}
	for _, table := range []string{"scope_grants", "research_jobs", "reports", "report_owners", "audit"} {
		rows, e := s.DB.Query("SELECT * FROM " + table + " ORDER BY 1,2")
		if e != nil {
			t.Fatal(e)
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			t.Fatal(e)
		}
		entries := [][]any{}
		for rows.Next() {
			values := make([]any, len(columns))
			ptrs := make([]any, len(columns))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if e = rows.Scan(ptrs...); e != nil {
				rows.Close()
				t.Fatal(e)
			}
			entries = append(entries, values)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, entries)
	}
	b, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func TestClaimRejectsCorruptedJobAndPolicyBeforeBudgetReservation(t *testing.T) {
	for _, kind := range []string{"payload", "policy"} {
		t.Run(kind, func(t *testing.T) {
			q, _, g, in := fixture(t)
			j, e := q.Enqueue("owner-a", "corrupt-input-key", in)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "payload":
				bad := in
				bad.Fixture = "different-fixture"
				b, _ := json.Marshal(bad)
				_, e = q.S.DB.Exec("UPDATE research_jobs SET payload=? WHERE id=?", string(b), j.ID)
			case "policy":
				_, e = q.S.DB.Exec("UPDATE policies SET document='{}' WHERE digest=?", in.PolicyDigest)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = q.Claim("worker"); e == nil {
				t.Fatal(fmt.Sprintf("corrupted %s accepted", kind))
			}
			grant, e := q.Grant("owner-a", g.Grant.ID)
			if e != nil || grant.RequestsRemaining != 4 {
				t.Fatal("budget changed before immutable input validation", grant, e)
			}
			job, e := q.Get("owner-a", j.ID)
			if e != nil || job.State != "queued" || job.Attempts != 0 {
				t.Fatal(job, e)
			}
		})
	}
}
