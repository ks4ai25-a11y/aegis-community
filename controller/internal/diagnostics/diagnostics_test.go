package diagnostics

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleContainsCountsNotContent(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	s.DB.Exec("INSERT INTO owners VALUES('owner-CANARY','hash-CANARY','now')")
	_, d, _ := s.Active()
	p := domain.Initial()
	p.Schema, p.Parent = "1.1", d
	p.Metadata.Rationale = "Register shop"
	p.Sites = []domain.SitePolicy{{ID: "site_shop", Name: "Shop", Hostnames: []string{"secret-host-CANARY.example.com"}, Origin: "origin-CANARY:3000", Mode: "protect", CRS: domain.CRS{Blocking: 1, Executing: 1, Threshold: 5}, Exclusions: []domain.Exclusion{}, TLS: "acme"}}
	b, _ := json.Marshal(p)
	s.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", domain.Digest(p), d, string(b), "ACTIVE", domain.Now(), "owner")
	s.DB.Exec("UPDATE settings SET value=? WHERE key='active'", domain.Digest(p))
	ev := domain.Event{ID: "e1", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: "site_shop", Request: "req-CANARY", Route: "/route-CANARY", Rules: []string{}, Source: "caddy-access"}
	eb, _ := json.Marshal(ev)
	s.DB.Exec("INSERT INTO events(id,at,request,source_key,document) VALUES('e1','x','req-CANARY','k',?)", string(eb))
	s.DB.Exec(`INSERT INTO incidents(id,summary,opened_at,state,severity,confidence,notes) VALUES('i1','summary-CANARY','now','open','low','high','{"detector_id":"DET-02"}')`)
	s.Set("canary_last", `{"outcome":"PASS","checked_at":"now","negative_request_id":"probe-CANARY"}`)
	out := Collect(s)
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "CANARY") {
		t.Fatal("bundle leaked content:", string(raw))
	}
	if out.Policy["registered_sites"] != 1 || out.Policy["tls_sites"] != 1 || out.Incidents["DET-02"] != 1 || out.Authority["owners"] != 1 || out.Database["quick_check"] != "ok" || out.Digest == "" {
		t.Fatal(string(raw))
	}
}
