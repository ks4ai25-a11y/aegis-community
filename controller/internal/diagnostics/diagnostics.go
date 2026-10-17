// SPDX-License-Identifier: BUSL-1.1
// Package diagnostics builds a privacy-preserving support bundle (v4 manual I4):
// versions, health, counters and counts only. It never includes events, request
// data, host names, origins, owner identities, credentials, tokens or policy text.
package diagnostics

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"database/sql"
	"encoding/json"
	"os"
)

const Schema = "1.0"

var Excluded = []string{"events and request metadata", "incident evidence", "host names, origins and routes", "owner identities and sessions", "credentials, tokens and keys", "policy and finding contents", "repository source"}

type Bundle struct {
	Schema    string         `json:"schema_version"`
	Generated string         `json:"generated_at"`
	Product   string         `json:"product_version"`
	Database  map[string]any `json:"database"`
	Policy    map[string]any `json:"policy"`
	Telemetry map[string]any `json:"telemetry"`
	Incidents map[string]int `json:"open_incidents_by_detector"`
	Jobs      map[string]any `json:"jobs"`
	Authority map[string]int `json:"active_authorities"`
	Canary    any            `json:"canary,omitempty"`
	Excluded  []string       `json:"excluded"`
	Digest    string         `json:"bundle_digest"`
}

func count(db *sql.DB, q string, args ...any) int {
	n := -1
	db.QueryRow(q, args...).Scan(&n)
	return n
}

func grouped(db *sql.DB, q string) map[string]int {
	out := map[string]int{}
	rows, e := db.Query(q)
	if e != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k sql.NullString
		var n int
		if rows.Scan(&k, &n) == nil {
			key := k.String
			if key == "" {
				key = "unknown"
			}
			out[key] = n
		}
	}
	return out
}

func setting(s *store.Store, key string) string {
	v, _ := s.Get(key)
	return v
}

// Collect gathers the bundle from an open (ideally read-only) store.
func Collect(s *store.Store) Bundle {
	db := s.DB
	b := Bundle{Schema: Schema, Generated: domain.Now(), Product: domain.Version, Excluded: Excluded}
	var check string
	db.QueryRow("PRAGMA quick_check").Scan(&check)
	size := int64(0)
	if st, e := os.Stat(s.Path); e == nil {
		size = st.Size()
	}
	b.Database = map[string]any{"schema_version": count(db, "SELECT max(version) FROM migrations"), "quick_check": check, "bytes": size, "audit_chain_consistent": s.VerifyAudit() == nil}
	p, digest, e := s.Active()
	b.Policy = map[string]any{"available": e == nil}
	if e == nil {
		modes := map[string]int{p.Mode: 1}
		tls, limited, exclusions := 0, 0, len(p.Exclusions)
		for _, site := range p.Sites {
			modes[site.Mode]++
			exclusions += len(site.Exclusions)
			if site.TLS != "" {
				tls++
			}
			if site.RateLimit != nil {
				limited++
			}
		}
		b.Policy = map[string]any{"available": true, "active_revision": digest, "schema_version": p.Schema, "registered_sites": len(p.Sites), "sites_by_mode": modes, "tls_sites": tls, "rate_limited_sites": limited, "exclusions": exclusions, "trusted_proxy_ranges": len(p.TrustedProxies), "apply_frozen": setting(s, "apply_frozen") == "true"}
	}
	b.Telemetry = map[string]any{"events_retained": count(db, "SELECT count(*) FROM events"), "events_dropped_total": setting(s, "events_dropped_total"), "ingest_rejected_total": setting(s, "ingest_rejected_total")}
	b.Incidents = grouped(db, "SELECT CASE WHEN json_valid(notes) THEN json_extract(notes,'$.detector_id') END,count(*) FROM incidents WHERE state='open' GROUP BY 1")
	b.Jobs = map[string]any{"research": grouped(db, "SELECT state,count(*) FROM research_jobs GROUP BY state"), "scanner": grouped(db, "SELECT state,count(*) FROM scanner_jobs GROUP BY state"), "scanner_dispatch": grouped(db, "SELECT state,count(*) FROM scanner_dispatch GROUP BY state")}
	b.Authority = map[string]int{"owners": count(db, "SELECT count(*) FROM owners"), "sessions": count(db, "SELECT count(*) FROM sessions WHERE expires>strftime('%s','now')"), "connector_credentials": count(db, "SELECT count(*) FROM connector_credentials WHERE state='active'"), "scanner_workers": count(db, "SELECT count(*) FROM scanner_workers WHERE state='active'"), "scope_grants": count(db, "SELECT count(*) FROM scope_grants WHERE state='active'")}
	if v := setting(s, "canary_last"); v != "" {
		var c map[string]any
		if json.Unmarshal([]byte(v), &c) == nil {
			// Keep the outcome only; the probe's request ID is not needed for support.
			b.Canary = map[string]any{"outcome": c["outcome"], "checked_at": c["checked_at"], "mode": c["mode"], "detail": c["detail"]}
		}
	}
	unsigned := b
	unsigned.Digest = ""
	b.Digest = domain.Digest(unsigned)
	return b
}
