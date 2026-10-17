package propose

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func seed(t *testing.T, site, route, target string, rule string) (*store.Store, string) {
	s, e := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	status := 200
	waf := domain.Event{ID: "ev-waf", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: site, Request: "req-1", Type: "waf_match", Decision: "unknown", Rules: []string{rule}, Source: "coraza", Target: target}
	acc := domain.Event{ID: "ev-acc", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: site, Request: "req-1", Type: "access", Decision: "observed", Method: "GET", Route: route, Status: &status, Rules: []string{}, Source: "caddy-access"}
	for i, ev := range []domain.Event{waf, acc} {
		b, _ := json.Marshal(ev)
		if _, e = s.DB.Exec("INSERT INTO events(id,at,request,source_key,document) VALUES(?,?,?,?,?)", ev.ID, ev.At, ev.Request, string(rune('a'+i)), string(b)); e != nil {
			t.Fatal(e)
		}
	}
	s.DB.Exec("INSERT INTO incidents(id,summary,opened_at,state,severity,confidence,notes) VALUES('inc','x','2026-10-16T12:00:00Z','open','medium','high','')")
	s.DB.Exec("INSERT INTO incident_events VALUES('inc','ev-waf')")
	return s, "inc"
}

func TestDemoProposalsAreValidCandidates(t *testing.T) {
	s, id := seed(t, "site_demo", "/catalog", "ARGS:query", "942100")
	r, e := Propose(s, id)
	if e != nil || len(r.Proposals) != 2 {
		t.Fatal(r, e)
	}
	_, active, _ := s.Active()
	for _, p := range r.Proposals {
		if p.Candidate.Parent != active || !p.Advisory || p.ID == "" || len(p.EvidenceRefs) == 0 {
			t.Fatal(p)
		}
	}
	// Protect (P2) is listed before the attacker-steerable exclusion (P3).
	if r.Proposals[0].Kind != "protect" || r.Proposals[0].Candidate.Mode != "protect" || len(r.Proposals[0].Candidate.Exclusions) != 0 {
		t.Fatal(r.Proposals[0])
	}
	x := r.Proposals[1]
	if !strings.Contains(x.SideEffects[0], "attacker can choose") {
		t.Fatal(x.SideEffects)
	}
	got := x.Candidate.Exclusions[0]
	expires, _ := time.Parse(time.RFC3339, got.ExpiresAt)
	if x.Kind != "exclusion" || len(x.Candidate.Exclusions) != 1 || got.RuleID != 942100 || got.Path != "/catalog" || got.Parameter != "query" || time.Until(expires) < 29*24*time.Hour || x.Candidate.Mode != "observe" {
		t.Fatal(x)
	}
}

func TestUnsafeOrUnknownExclusionsAreExplainedNotProposed(t *testing.T) {
	// A templated route cannot become an exact exclusion.
	s, id := seed(t, "site_demo", "/api/users/{id}", "ARGS:q", "942100")
	r, _ := Propose(s, id)
	for _, p := range r.Proposals {
		if p.Kind == "exclusion" {
			t.Fatal("exclusion proposed for templated route", p)
		}
	}
	if len(r.NotProposed) == 0 {
		t.Fatal("no explanation")
	}
	// No recorded parameter name.
	s, id = seed(t, "site_demo", "/catalog", "", "942100")
	r, _ = Propose(s, id)
	if len(r.Proposals) != 1 || r.Proposals[0].Kind != "protect" {
		t.Fatal(r)
	}
	// Anomaly evaluation rule cannot be excluded for the demo either.
	s, id = seed(t, "site_demo", "/catalog", "ARGS:query", "949110")
	r, _ = Propose(s, id)
	for _, p := range r.Proposals {
		if p.Kind == "exclusion" {
			t.Fatal("anomaly rule exclusion proposed")
		}
	}
}

func TestBehaviouralDetectorsAreAdvisoryOnly(t *testing.T) {
	s, id := seed(t, "site_demo", "/catalog", "ARGS:query", "942100")
	s.DB.Exec(`UPDATE incidents SET notes='{"detector_id":"DET-02"}' WHERE id=?`, id)
	r, e := Propose(s, id)
	if e != nil || len(r.Proposals) != 0 || len(r.NotProposed) != 1 {
		t.Fatal(r, e)
	}
}

func TestBurstProposesRateLimitForRegisteredSite(t *testing.T) {
	s, id := seed(t, "site_shop", "/catalog", "", "942100")
	_, d, _ := s.Active()
	p := domain.Initial()
	p.Schema, p.Parent = "1.1", d
	p.Metadata.Rationale = "Register shop"
	p.Sites = []domain.SitePolicy{{ID: "site_shop", Name: "Shop", Hostnames: []string{"shop.example.com"}, Origin: "shop:3000", Mode: "observe", CRS: domain.CRS{Blocking: 1, Executing: 1, Threshold: 5}, Exclusions: []domain.Exclusion{}}}
	b, _ := json.Marshal(p)
	s.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", domain.Digest(p), d, string(b), "ACTIVE", domain.Now(), "owner")
	s.DB.Exec("UPDATE settings SET value=? WHERE key='active'", domain.Digest(p))
	s.DB.Exec(`UPDATE incidents SET notes='{"detector_id":"DET-04","site_id":"site_shop"}' WHERE id=?`, id)
	r, e := Propose(s, id)
	if e != nil || len(r.Proposals) != 1 || r.Proposals[0].Kind != "rate_limit" {
		t.Fatal(r, e)
	}
	got := r.Proposals[0].Candidate.Sites[0].RateLimit
	if got == nil || got.Requests != 600 || got.WindowSeconds != 60 || r.Proposals[0].Candidate.Parent != domain.Digest(p) {
		t.Fatal(r.Proposals[0].Candidate)
	}
	// Demo bursts are explained, not proposed.
	s.DB.Exec(`UPDATE incidents SET notes='{"detector_id":"DET-04","site_id":"site_demo"}' WHERE id=?`, id)
	if r, _ = Propose(s, id); len(r.Proposals) != 0 || len(r.NotProposed) != 1 {
		t.Fatal(r)
	}
}
