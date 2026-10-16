package expiry

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func setup(t *testing.T, expires string) (*store.Store, string) {
	s, e := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	s.DB.Exec("INSERT INTO owners VALUES('owner','x','now')")
	_, d, _ := s.Active()
	p := domain.Initial()
	p.Parent = d
	p.Metadata.Rationale = "Temporary exclusion"
	p.Exclusions = []domain.Exclusion{{RuleID: 942100, Method: "GET", Path: "/catalog", Parameter: "query", ExpiresAt: expires}, {RuleID: 941100, Method: "GET", Path: "/catalog", Parameter: "q"}}
	b, _ := json.Marshal(p)
	s.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", domain.Digest(p), d, string(b), "ACTIVE", domain.Now(), "owner")
	s.DB.Exec("UPDATE settings SET value=? WHERE key='active'", domain.Digest(p))
	return s, domain.Digest(p)
}

func report(outcome string) domain.Report {
	r := domain.Report{Schema: "1.0", ID: "r", Overall: outcome}
	r.Digest = domain.Digest(r)
	return r
}

func TestExpiredExclusionRemovedAfterFixturePass(t *testing.T) {
	s, parent := setup(t, "2026-10-01T00:00:00Z")
	var applied domain.Policy
	w := &Worker{S: s, Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) },
		Verify: func(_ context.Context, p domain.Policy) (domain.Report, error) { return report("PASS"), nil },
		Apply:  func(_ context.Context, p domain.Policy, actor string) error { applied = p; return nil }}
	o := w.Tick(context.Background())
	if o.Err != nil || o.Applied == "" || len(applied.Exclusions) != 1 || applied.Exclusions[0].RuleID != 941100 || applied.Parent != parent {
		t.Fatal(o, applied)
	}
	var state string
	s.DB.QueryRow("SELECT state FROM policies WHERE digest=?", o.Applied).Scan(&state)
	if state != "PENDING_APPROVAL" {
		t.Fatal("candidate not staged for Apply", state)
	}
}

func TestFailedFixtureKeepsExclusionAndRaisesIncident(t *testing.T) {
	s, _ := setup(t, "2026-10-01T00:00:00Z")
	called := false
	w := &Worker{S: s, Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) },
		Verify: func(_ context.Context, p domain.Policy) (domain.Report, error) { return report("FAIL"), nil },
		Apply:  func(context.Context, domain.Policy, string) error { called = true; return nil }}
	o := w.Tick(context.Background())
	if called || o.Applied != "" || o.Incident == "" {
		t.Fatal(o)
	}
}

func TestUnexpiredDoesNothing(t *testing.T) {
	s, _ := setup(t, "2027-01-01T00:00:00Z")
	w := &Worker{S: s, Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) },
		Verify: func(context.Context, domain.Policy) (domain.Report, error) {
			t.Fatal("verified")
			return domain.Report{}, nil
		}}
	if o := w.Tick(context.Background()); o.Changed {
		t.Fatal(o)
	}
}

func TestFailedActivationIsRetried(t *testing.T) {
	s, _ := setup(t, "2026-10-01T00:00:00Z")
	calls := 0
	w := &Worker{S: s, Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) },
		Verify: func(context.Context, domain.Policy) (domain.Report, error) { return report("PASS"), nil },
		Apply: func(_ context.Context, p domain.Policy, _ string) error {
			calls++
			if calls == 1 {
				s.DB.Exec("UPDATE policies SET state='FAILED' WHERE digest=?", domain.Digest(p))
				return context.DeadlineExceeded
			}
			var state string
			s.DB.QueryRow("SELECT state FROM policies WHERE digest=?", domain.Digest(p)).Scan(&state)
			if state != "PENDING_APPROVAL" {
				t.Fatal("failed candidate not re-armed", state)
			}
			return nil
		}}
	if o := w.Tick(context.Background()); o.Err == nil {
		t.Fatal("first failure not reported")
	}
	if o := w.Tick(context.Background()); o.Applied == "" || calls != 2 {
		t.Fatal("expiry not retried", o, calls)
	}
}
