// SPDX-License-Identifier: Apache-2.0
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/ingest"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/research"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/store"
	"aegis.local/controller/internal/verify"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	S         *store.Store
	A         *auth.Auth
	P         *policy.Manager
	I         *ingest.Ingestor
	V         verify.Client
	Q         *research.Queue
	R         *repository.Registry
	Scans     *scanqueue.Queue
	Assets    string
	mutations sync.Mutex
	streams   chan struct{}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/", s.api)
	mux.Handle("/", http.FileServer(http.Dir(s.Assets)))
	s.streams = make(chan struct{}, 5)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" {
			origin := r.Header.Get("Origin")
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if origin != "" && origin != scheme+"://"+r.Host {
				fail(w, 403, "FORBIDDEN", "Cross-origin mutation denied")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func output(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, msg string) {
	output(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg, "request_id": domain.ID(), "retryable": status >= 500}})
}
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "/health/live" {
		output(w, 200, map[string]bool{"live": true})
		return
	}
	if path == "/health/ready" {
		if s.S.DB.Ping() != nil {
			fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Database unavailable")
			return
		}

		_, active, e := s.S.Active()
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		gateway, ge := s.P.Active(ctx)
		if e != nil || ge != nil || gateway != active || s.P.Frozen.Load() {
			fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Policy deployment is not ready")
			return
		}
		output(w, 200, map[string]bool{"ready": true})
		return
	}
	if path == "/auth/bootstrap" || path == "/auth/login" {
		if r.Method != "POST" {
			fail(w, 405, "VALIDATION_FAILED", "POST required")
			return
		}
		if !s.A.Throttle() {
			fail(w, 429, "RATE_LIMITED", "Wait before retrying enrollment or login")
			return
		}
		var in struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if auth.Decode(r, &in) != nil {
			fail(w, 400, "VALIDATION_FAILED", "Invalid authentication request")
			return
		}
		if path == "/auth/bootstrap" {
			if e := s.A.Enroll(in.Token, in.Password); e != nil {
				fail(w, 403, "FORBIDDEN", e.Error())
				return
			}
		}
		csrf, e := s.A.Login(w, r, in.Password)
		if e != nil {
			fail(w, 403, "FORBIDDEN", "Invalid credentials")
			return
		}
		s.A.Reset()
		s.S.Audit("owner", "auth.login", "session", "success", nil)
		output(w, 200, map[string]string{"csrf_token": csrf})
		return
	}
	actor, session, e := s.A.Session(r)
	if e != nil {
		fail(w, 401, "NOT_AUTHENTICATED", "Sign in; state changes also require a valid CSRF token")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if !s.mutations.TryLock() {
			fail(w, 429, "RATE_LIMITED", "Another state change is in progress")
			return
		}
		defer s.mutations.Unlock()
	}
	switch {
	case path == "/findings/catalogue" && r.Method == "GET":
		s.findingCatalogue(w, r, actor)
	case path == "/findings" && r.Method == "GET":
		s.findings(w, r, actor)
	case path == "/scans" || strings.HasPrefix(path, "/scans/"):
		s.scanOperation(w, r, actor, path)
	case path == "/repos" || strings.HasPrefix(path, "/repos/"):
		s.repositoryOperation(w, r, actor, path)
	case path == "/auth/session" && r.Method == "GET":
		csrf, e := s.A.RotateCSRF(session)
		if e != nil {
			fail(w, 500, "INTERNAL_ERROR", "Session unavailable")
			return
		}
		output(w, 200, map[string]string{"owner_id": actor, "csrf_token": csrf})
	case path == "/auth/logout" && r.Method == "POST":
		s.S.DB.Exec("DELETE FROM sessions WHERE hash=?", session)
		http.SetCookie(w, &http.Cookie{Name: "aegis_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		output(w, 200, map[string]bool{"logged_out": true})
	case path == "/system/status" && r.Method == "GET":
		s.status(w, r)
	case path == "/sites" && r.Method == "GET":
		s.sites(w)
	case strings.HasPrefix(path, "/sites/"):
		site, rest, ok := s.siteRoute(path)
		if !ok {
			fail(w, 404, "RESOURCE_NOT_FOUND", "Site not registered in the active policy")
			return
		}
		switch {
		case rest == "/events" && r.Method == "GET":
			s.events(w, r, site)
		case rest == "/events/stream" && r.Method == "GET":
			s.stream(w, r, site)
		case rest == "/endpoints" && r.Method == "GET":
			s.endpoints(w, r, site)
		case rest == "/incidents" && r.Method == "GET":
			s.incidents(w, r, site)
		case rest == "/policy" && r.Method == "GET":
			// One gateway revision governs every site; it is returned whole.
			p, d, e := s.S.Active()
			if e != nil {
				fail(w, 500, "INTERNAL_ERROR", "Policy unavailable")
				return
			}
			w.Header().Set("ETag", `"`+d+`"`)
			output(w, 200, map[string]any{"digest": d, "policy": p})
		case rest == "/policies/validate" && r.Method == "POST":
			s.preview(w, r, actor)
		case rest == "/policies" && r.Method == "POST":
			s.draft(w, r, actor)
		case rest == "/policies/history" && r.Method == "GET":
			s.history(w)
		case strings.HasPrefix(rest, "/policies/") && r.Method == "POST":
			s.activate(w, r, actor, path, strings.TrimPrefix(rest, "/policies/"))
		default:
			fail(w, 404, "RESOURCE_NOT_FOUND", "Endpoint not available in this alpha")
		}
	case strings.HasPrefix(path, "/incidents/") && r.Method == "GET":
		s.incident(w, strings.TrimPrefix(path, "/incidents/"))
	case path == "/verify/fixtures" && r.Method == "GET":
		output(w, 200, map[string]any{"items": []any{map[string]string{"fixture_id": verify.Fixture, "fixture_digest": verify.FixtureDigest(), "scope": "bundled-synthetic-fixture"}}})
	case (path == "/verify/jobs" || path == "/verifications") && r.Method == "POST":
		s.enqueueVerification(w, r, actor)
	case path == "/verifications" && r.Method == "GET":
		s.listJobs(w, actor)
	case strings.HasPrefix(path, "/verifications/"):
		s.jobOperation(w, r, actor, strings.TrimPrefix(path, "/verifications/"))
	case path == "/scope-grants" || strings.HasPrefix(path, "/scope-grants/"):
		s.scopeOperation(w, r, actor, path)
	case strings.HasPrefix(path, "/verify/reports/") && r.Method == "GET":
		s.reportDocument(w, actor, strings.TrimPrefix(path, "/verify/reports/"))
	case strings.HasPrefix(path, "/verify/jobs/") && r.Method == "GET":
		s.jobOperation(w, r, actor, strings.TrimPrefix(path, "/verify/jobs/"))
	case path == "/audit" && r.Method == "GET":
		rows, e := s.S.DB.Query("SELECT seq,document,previous,hash FROM audit ORDER BY seq DESC LIMIT 100")
		if e != nil {
			fail(w, 500, "INTERNAL_ERROR", "Audit unavailable")
			return
		}
		defer rows.Close()
		items := []any{}
		for rows.Next() {
			var seq int
			var b, p, h string
			rows.Scan(&seq, &b, &p, &h)
			items = append(items, map[string]any{"seq": seq, "record": json.RawMessage(b), "previous_hash": p, "hash": h})
		}
		output(w, 200, map[string]any{"items": items, "local_trust_limit": "A host administrator can replace the entire local chain."})
	case path == "/settings/privacy" && r.Method == "GET":
		output(w, 200, map[string]any{"event_retention_days": 7, "max_events": 50000, "max_database_bytes": 268435456, "raw_bodies": false, "sensitive_headers": false, "query_values": false, "telemetry_upload": false, "ai_background_jobs": "not configured", "scope": "demo-only"})
	case path == "/demo/traffic" && r.Method == "POST":
		s.demo(w, r)
	default:
		fail(w, 404, "RESOURCE_NOT_FOUND", "Endpoint not available in this alpha")
	}
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	p, d, e := s.S.Active()
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Policy unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	g, ge := s.P.Active(ctx)
	var total int
	s.S.DB.QueryRow("SELECT count(*) FROM events").Scan(&total)
	var incidents int
	s.S.DB.QueryRow("SELECT count(*) FROM incidents WHERE state='open'").Scan(&incidents)
	size := int64(0)
	if st, e := os.Stat(s.S.Path); e == nil {
		size = st.Size()
	}
	output(w, 200, map[string]any{"version": domain.Version, "release_maturity": "internal-alpha", "mode": p.Mode, "active_revision": d, "gateway_revision": g, "gateway_healthy": ge == nil && g == d, "apply_frozen": s.P.Frozen.Load(), "requests_retained": total, "counter_definition": "retained source records; WAF and access are separate records, not total requests", "open_incidents": incidents, "events_dropped_total": s.I.Dropped.Load(), "ingest_rejected_total": s.I.Rejected.Load(), "last_ingest_unix": s.I.Last.Load(), "database_bytes": size, "external_services_required": false})
}

// siteRoute splits /sites/{id}/rest and accepts only sites governed by the active policy.
func (s *Server) siteRoute(path string) (site, rest string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/sites/")
	site, rest, _ = strings.Cut(trimmed, "/")
	rest = "/" + rest
	p, _, e := s.S.Active()
	if e != nil {
		return "", "", false
	}
	for _, id := range p.SiteIDs() {
		if id == site {
			return site, rest, true
		}
	}
	return "", "", false
}
func (s *Server) sites(w http.ResponseWriter) {
	p, d, e := s.S.Active()
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Policy unavailable")
		return
	}
	items := []any{map[string]any{"site_id": "site_demo", "display_name": "Bundled demo", "hostname": "demo.example.test", "hostnames": []string{"demo.example.test"}, "origin_url": "http://demo-origin:8080", "mode": p.Mode, "synthetic": true}}
	for _, site := range p.Sites {
		items = append(items, map[string]any{"site_id": site.ID, "display_name": site.Name, "hostname": site.Hostnames[0], "hostnames": site.Hostnames, "origin_url": "http://" + site.Origin, "mode": site.Mode, "synthetic": false})
	}
	output(w, 200, map[string]any{"items": items, "cursor": nil, "policy_digest": d})
}
func limit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 50
	}
	return min(n, 100)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request, site string) {
	cursor, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
	rows, e := s.S.DB.Query("SELECT seq,document FROM events WHERE seq>? AND json_extract(document,'$.site_id')=? ORDER BY seq LIMIT ?", cursor, site, limit(r))
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Events unavailable")
		return
	}
	defer rows.Close()
	items := []any{}
	last := cursor
	for rows.Next() {
		var seq int
		var b string
		rows.Scan(&seq, &b)
		items = append(items, map[string]any{"cursor": seq, "event": json.RawMessage(b)})
		last = seq
	}
	output(w, 200, map[string]any{"items": items, "cursor": last})
}
func (s *Server) stream(w http.ResponseWriter, r *http.Request, site string) {
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		fail(w, 429, "RATE_LIMITED", "Stream limit reached")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	cursor, _ := strconv.Atoi(r.Header.Get("Last-Event-ID"))
	var first int
	s.S.DB.QueryRow("SELECT coalesce(min(seq),0) FROM events").Scan(&first)
	if cursor > 0 && cursor < first {
		fmt.Fprintf(w, "event: loss\ndata: {\"earliest_cursor\":%d}\n\n", first)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	deadline := time.After(10 * time.Minute)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			return
		case <-ticker.C:
			rows, e := s.S.DB.Query("SELECT seq,document,json_extract(document,'$.site_id')=? FROM events WHERE seq>? ORDER BY seq LIMIT 100", site, cursor)
			if e != nil {
				return
			}
			for rows.Next() {
				var seq int
				var b string
				var match bool
				rows.Scan(&seq, &b, &match)
				if match {
					fmt.Fprintf(w, "id: %d\nevent: event\ndata: %s\n\n", seq, b)
				}
				cursor = seq
			}
			rows.Close()
			fmt.Fprint(w, "event: heartbeat\ndata: {}\n\n")
			flusher.Flush()
		}
	}
}

// incidentSite derives an incident's site from its linked evidence; incidents whose
// evidence aged out are listed under the bundled demo, where they originated.
const incidentSite = "coalesce((SELECT json_extract(e.document,'$.site_id') FROM incident_events ie JOIN events e ON e.id=ie.event WHERE ie.incident=incidents.id LIMIT 1),'site_demo')"

func (s *Server) incidents(w http.ResponseWriter, r *http.Request, site string) {
	rows, e := s.S.DB.Query("SELECT id,summary,opened_at,state,severity,confidence FROM incidents WHERE "+incidentSite+"=? ORDER BY opened_at DESC LIMIT ?", site, limit(r))
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Incidents unavailable")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var id, sum, at, state, sev, conf string
		rows.Scan(&id, &sum, &at, &state, &sev, &conf)
		items = append(items, map[string]any{"incident_id": id, "summary": sum, "opened_at": at, "state": state, "severity": sev, "confidence": conf, "synthetic": site == "site_demo", "label_source": "rule_match_observation"})
	}
	output(w, 200, map[string]any{"items": items})
}
func (s *Server) incident(w http.ResponseWriter, id string) {
	var sum, at, state, sev, conf, site string
	if e := s.S.DB.QueryRow("SELECT summary,opened_at,state,severity,confidence,"+incidentSite+" FROM incidents WHERE id=?", id).Scan(&sum, &at, &state, &sev, &conf, &site); e != nil {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Incident not found")
		return
	}
	rows, e := s.S.DB.Query("SELECT e.document FROM events e JOIN incident_events i ON e.id=i.event WHERE i.incident=? LIMIT 50", id)
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Evidence unavailable")
		return
	}
	defer rows.Close()
	events := []json.RawMessage{}
	for rows.Next() {
		var b string
		rows.Scan(&b)
		events = append(events, json.RawMessage(b))
	}
	output(w, 200, map[string]any{"incident_id": id, "site_id": site, "summary": sum, "opened_at": at, "state": state, "severity": sev, "confidence": conf, "synthetic": site == "site_demo", "evidence": events, "unknowns": []string{"Pattern detection does not prove successful exploitation.", "Retained evidence may be incomplete after retention or telemetry loss.", "Source attribution and application authorization were not assessed."}})
}
func (s *Server) endpoints(w http.ResponseWriter, r *http.Request, site string) {
	rows, e := s.S.DB.Query("SELECT document FROM events WHERE json_extract(document,'$.source')='caddy-access' AND json_extract(document,'$.site_id')=? ORDER BY seq DESC LIMIT 50000", site)
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Inventory unavailable")
		return
	}
	defer rows.Close()
	counts := map[string]int{}
	statuses := map[string]map[string]int{}
	for rows.Next() {
		var b string
		rows.Scan(&b)
		var ev domain.Event
		json.Unmarshal([]byte(b), &ev)
		if ev.Source != "caddy-access" || ev.Route == "" {
			continue
		}
		key := ev.Method + " " + ev.Route
		counts[key]++
		if statuses[key] == nil {
			statuses[key] = map[string]int{}
		}
		if ev.Status != nil {
			statuses[key][fmt.Sprintf("%dxx", *ev.Status/100)]++
		}
	}
	items := []any{}
	for key, n := range counts {
		parts := strings.SplitN(key, " ", 2)
		items = append(items, map[string]any{"method": parts[0], "route_template": parts[1], "requests_retained": n, "status_classes": statuses[key], "source": "observed-traffic", "authorization_assessed": false})
	}
	output(w, 200, map[string]any{"items": items, "limitation": "Object identifiers do not establish BOLA; application authorization remains the application's responsibility."})
}
func (s *Server) preview(w http.ResponseWriter, r *http.Request, actor string) {
	var p domain.Policy
	if auth.Decode(r, &p) != nil {
		fail(w, 400, "VALIDATION_FAILED", "Invalid typed policy")
		return
	}
	current, active, e := s.S.Active()
	if e != nil || p.Parent != active {
		fail(w, 409, "CONFLICT", "Refresh the active policy before previewing")
		return
	}
	if e = policy.ProtectRequiresObservation(current, p); e != nil {
		fail(w, 400, "VALIDATION_FAILED", e.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	d, e := s.P.Prepare(ctx, p)
	if e != nil {
		fail(w, 400, "VALIDATION_FAILED", e.Error())
		return
	}
	report, e := s.V.Run(ctx, p)
	if e != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", e.Error())
		return
	}
	if e = s.S.SaveReport(actor, report); e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Report could not be stored")
		return
	}
	s.S.Set("preview:"+d, report.Digest)
	s.S.Audit(actor, "policy.preview", d, report.Overall, nil)
	output(w, 200, map[string]any{"candidate_digest": d, "current_digest": active, "validation": "gateway-validated", "fixture_result": report.Overall, "report": report, "unknowns": []string{"Production false-positive rate is unknown.", "Application authorization is not verified."}})
}
func (s *Server) draft(w http.ResponseWriter, r *http.Request, actor string) {
	var p domain.Policy
	if auth.Decode(r, &p) != nil || policy.Validate(p) != nil {
		fail(w, 400, "VALIDATION_FAILED", "Invalid typed policy")
		return
	}
	d := domain.Digest(p)
	proof, e := s.S.Get("preview:" + d)
	if e != nil || proof == "" {
		fail(w, 409, "CONFLICT", "Preview this exact candidate first")
		return
	}
	b, _ := json.Marshal(p)
	_, e = s.S.DB.Exec("INSERT OR IGNORE INTO policies VALUES(?,?,?,?,?,?)", d, p.Parent, string(b), "PENDING_APPROVAL", domain.Now(), actor)
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Draft not saved")
		return
	}
	output(w, 201, map[string]string{"digest": d, "state": "PENDING_APPROVAL"})
}
func (s *Server) activate(w http.ResponseWriter, r *http.Request, actor, path, operation string) {
	parts := strings.Split(operation, "/")
	if len(parts) != 2 {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Policy operation not found")
		return
	}
	var in struct {
		Reason string `json:"reason"`
		Ack    bool   `json:"acknowledge_disruption_risk"`
	}
	if auth.Decode(r, &in) != nil || !in.Ack || len(in.Reason) < 5 {
		fail(w, 400, "VALIDATION_FAILED", "Explicit disruption acknowledgement and reason required")
		return
	}
	p, e := s.S.Policy(parts[0])
	if e != nil {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Policy not found")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 {
		fail(w, 400, "VALIDATION_FAILED", "Idempotency key required")
		return
	}
	content := domain.Digest(map[string]any{"path": path, "body": in, "parent": r.Header.Get("If-Match")})
	var saved, hash string
	e = s.S.DB.QueryRow("SELECT content_hash,response FROM idempotency WHERE key=?", key).Scan(&hash, &saved)
	if e == nil {
		if hash != content {
			fail(w, 409, "CONFLICT", "Idempotency key reused with different content")
			return
		}
		output(w, 200, json.RawMessage(saved))
		return
	}
	if e != sql.ErrNoRows {
		fail(w, 500, "INTERNAL_ERROR", "Idempotency record unavailable")
		return
	}
	_, active, e := s.S.Active()
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Active policy unavailable")
		return
	}
	if r.Header.Get("If-Match") != `"`+active+`"` {
		fail(w, 412, "CONFLICT", "Active policy changed")
		return
	}
	if parts[1] == "rollback" {
		p.Parent = active
		p.Metadata = domain.Metadata{Rationale: in.Reason, RequestedBy: actor}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		if _, e = s.P.Prepare(ctx, p); e != nil {
			fail(w, 400, "VALIDATION_FAILED", e.Error())
			return
		}
		report, e := s.V.Run(ctx, p)
		if e != nil || report.Overall != "PASS" {
			fail(w, 409, "CONFLICT", "Rollback fixture could not be confirmed")
			return
		}
		d := domain.Digest(p)
		b, _ := json.Marshal(p)
		// A rollback to a digest that previously failed is re-armed rather than ignored.
		if _, e = s.S.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?) ON CONFLICT(digest) DO UPDATE SET state='PENDING_APPROVAL',parent=excluded.parent WHERE policies.state='FAILED'", d, active, string(b), "PENDING_APPROVAL", domain.Now(), actor); e != nil {
			fail(w, 500, "INTERNAL_ERROR", "Rollback candidate could not be recorded")
			return
		}
	} else if parts[1] == "activate" {
		proof, e := s.S.Get("preview:" + parts[0])
		if e != nil {
			fail(w, 409, "CONFLICT", "Exact candidate preview required")
			return
		}
		var raw string
		s.S.DB.QueryRow("SELECT document FROM reports WHERE digest=?", proof).Scan(&raw)
		var report domain.Report
		json.Unmarshal([]byte(raw), &report)
		if report.Overall != "PASS" {
			fail(w, 409, "CONFLICT", "Controlled preview did not pass")
			return
		}
	} else {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Unknown policy action")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if e = s.P.Apply(ctx, p, actor); e != nil {
		fail(w, 409, "CONFLICT", e.Error())
		return
	}
	response := map[string]string{"state": "ACTIVE", "digest": domain.Digest(p)}
	b, _ := json.Marshal(response)
	s.S.DB.Exec("INSERT INTO idempotency VALUES(?,?,?)", key, content, string(b))
	output(w, 200, response)
}
func (s *Server) history(w http.ResponseWriter) {
	rows, e := s.S.DB.Query("SELECT digest,parent,state,created_at,document FROM policies ORDER BY created_at DESC LIMIT 50")
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "History unavailable")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var d, p, st, at, b string
		rows.Scan(&d, &p, &st, &at, &b)
		items = append(items, map[string]any{"digest": d, "parent": p, "state": st, "created_at": at, "policy": json.RawMessage(b)})
	}
	output(w, 200, map[string]any{"items": items})
}
func (s *Server) document(w http.ResponseWriter, table, column, id string) {
	var raw string
	e := s.S.DB.QueryRow("SELECT document FROM "+table+" WHERE "+column+"=?", id).Scan(&raw)
	if e == sql.ErrNoRows {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Record not found")
		return
	}
	if e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Record unavailable")
		return
	}
	output(w, 200, json.RawMessage(raw))
}
func (s *Server) demo(w http.ResponseWriter, r *http.Request) {
	h := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	out := []any{}
	for _, path := range verify.Corpus {
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "http://gateway:8080"+path, nil)
		req.Host = "demo.example.test"
		resp, e := h.Do(req)
		if e != nil {
			fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Demo gateway unavailable")
			return
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		out = append(out, map[string]any{"status": resp.StatusCode, "request_id": resp.Header.Get("X-Aegis-Request-ID"), "revision": resp.Header.Get("X-Aegis-Revision")})
	}
	output(w, 200, map[string]any{"synthetic": true, "results": out})
}
