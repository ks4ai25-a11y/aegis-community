// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/connector"
	"aegis.local/controller/internal/research"
	"aegis.local/controller/internal/store"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConnectorCredentialIsReadOnlyAndRevocable(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	if e = a.Enroll(a.Bootstrap, "a sufficiently long test passphrase"); e != nil {
		t.Fatal(e)
	}
	login := httptest.NewRecorder()
	csrf, e := a.Login(login, httptest.NewRequest("POST", "http://localhost", nil), "a sufficiently long test passphrase")
	if e != nil {
		t.Fatal(e)
	}
	cookie := login.Result().Cookies()[0]
	s.DB.Exec("INSERT INTO incidents(id,summary,opened_at,state,severity,confidence) VALUES('inc-1','Synthetic request matched CRS rule 942100','2026-10-16T12:00:00Z','open','medium','high')")
	server := &Server{S: s, A: a, Q: &research.Queue{S: s}, Assets: t.TempDir(), Connectors: &connector.Registry{S: s}}
	handler := server.Handler()
	send := func(method, path string, body any, headers map[string]string, withCookie bool) (int, map[string]any) {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, "http://localhost/api/v1"+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if withCookie {
			req.AddCookie(cookie)
			req.Header.Set("X-CSRF-Token", csrf)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := send("POST", "/connectors", map[string]any{"name": "Claude Desktop", "lifetime_hours": 0}, nil, true); code != 400 {
		t.Fatal("zero lifetime accepted", code)
	}
	code, out := send("POST", "/connectors", map[string]any{"name": "Claude Desktop", "lifetime_hours": 24}, nil, true)
	if code != 201 {
		t.Fatal(code, out)
	}
	token := out["token"].(string)
	id := out["connector"].(map[string]any)["connector_id"].(string)
	bearer := map[string]string{"Authorization": "Bearer " + token}

	for _, ok := range []string{"/sites", "/sites/site_demo/incidents", "/incidents/inc-1"} {
		if code, out := send("GET", ok, nil, bearer, false); code == 401 || code == 403 {
			t.Fatal("connector refused allowed read", ok, code, out)
		}
	}
	// Mutations, credential management, scanner and research routes stay closed.
	refused := []struct{ method, path string }{
		{"POST", "/sites/site_demo/policies/validate"}, {"POST", "/incidents/inc-1/assessment"}, {"POST", "/connectors"},
		{"GET", "/connectors"}, {"GET", "/audit"}, {"GET", "/verifications"}, {"GET", "/scans"}, {"GET", "/repositories"},
		{"POST", "/auth/logout"},
	}
	for _, r := range refused {
		if code, _ := send(r.method, r.path, map[string]any{}, bearer, false); code != 403 && code != 401 {
			t.Fatal("connector reached", r.method, r.path, code)
		}
	}
	// Dot segments are cleaned by the router (redirect only); the cleaned route is still refused.
	if code, _ := send("GET", "/incidents/inc-1/../../audit", nil, bearer, false); code != 307 {
		t.Fatal("dot-segment path not redirected", code)
	}
	// A connector header never piggybacks on an owner session.
	if code, _ := send("POST", "/connectors", map[string]any{"name": "x", "lifetime_hours": 2}, bearer, true); code != 403 {
		t.Fatal("bearer plus cookie escalated", code)
	}
	for _, bad := range []string{"Bearer aegis_ct_00", "Basic " + token, "Bearer " + token + "x"} {
		if code, _ := send("GET", "/sites", nil, map[string]string{"Authorization": bad}, false); code != 401 {
			t.Fatal("malformed credential accepted", bad, code)
		}
	}
	code, out = send("GET", "/connectors", nil, nil, true)
	if items := out["items"].([]any); code != 200 || len(items) != 1 || items[0].(map[string]any)["last_used_unix"].(float64) == 0 {
		t.Fatal("list/last_used", code, out)
	}
	t.Run("owner preview and single use handoff", func(t *testing.T) {
		if _, err := s.DB.Exec(`INSERT INTO events(id,at,request,source_key,document) VALUES('raw-event','2026-10-16T12:41:00Z','raw-request','fixture-key','{"client_key":"PRIVATE-CANARY","route_template":"PRIVATE-CANARY","decision":"blocked","rule_ids":["942100","PRIVATE-CANARY"]}');
  INSERT INTO incident_events(incident,event) VALUES('inc-1','raw-event')`); err != nil {
			t.Fatal(err)
		}
		previewPath := "/desktop/handoff-preview?incident_id=inc-1"
		if code, _ := send("GET", previewPath, nil, bearer, true); code != 403 {
			t.Fatalf("connector preview: %d", code)
		}
		code, p := send("GET", previewPath, nil, nil, true)
		if code != 200 {
			t.Fatalf("preview: %d", code)
		}
		previewBytes, _ := json.Marshal(p)
		if strings.Contains(string(previewBytes), "PRIVATE-CANARY") || strings.Contains(string(previewBytes), "raw-event") || !strings.Contains(string(previewBytes), "942100") {
			t.Fatal("preview did not isolate approved fields")
		}
		in := map[string]any{"incident_id": "inc-1", "connector_id": id, "preview_digest": p["preview_digest"], "approve_redacted_export": false}
		if code, _ := send("POST", "/desktop/handoffs", in, nil, true); code != 403 {
			t.Fatalf("no consent: %d", code)
		}
		in["approve_redacted_export"] = true
		if code, _ := send("POST", "/desktop/handoffs", in, map[string]string{"X-CSRF-Token": "invalid"}, true); code != 401 {
			t.Fatalf("bad CSRF: %d", code)
		}
		in["preview_digest"] = "sha256:" + strings.Repeat("0", 64)
		if code, _ := send("POST", "/desktop/handoffs", in, nil, true); code != 409 {
			t.Fatalf("stale preview: %d", code)
		}
		in["preview_digest"] = p["preview_digest"]
		if code, _ := send("POST", "/desktop/handoffs", in, bearer, true); code != 403 {
			t.Fatalf("connector approval: %d", code)
		}
		create := func() string {
			t.Helper()
			code, h := send("POST", "/desktop/handoffs", in, nil, true)
			if code != 201 {
				t.Fatalf("approval: %d %v", code, h)
			}
			return "/desktop/handoffs/" + h["handoff_id"].(string)
		}
		path := create()
		if code, _ := send("GET", path, nil, nil, true); code != 403 {
			t.Fatalf("owner consumed connector handoff: %d", code)
		}
		code, other := send("POST", "/connectors", map[string]any{"name": "Other Desktop", "lifetime_hours": 1}, nil, true)
		if code != 201 {
			t.Fatal(code)
		}
		if code, _ := send("GET", path, nil, map[string]string{"Authorization": "Bearer " + other["token"].(string)}, false); code != 404 {
			t.Fatalf("wrong connector: %d", code)
		}
		code, actual := send("GET", path, nil, bearer, false)
		expected, _ := json.Marshal(p["bundle"])
		got, _ := json.Marshal(actual)
		if code != 200 || !bytes.Equal(expected, got) {
			t.Fatal("delivery differed from the approved preview", code)
		}
		if code, _ := send("GET", path, nil, bearer, false); code != 404 {
			t.Fatalf("second delivery: %d", code)
		}
		revoked := create()
		if code, _ := send("POST", revoked+"/revoke", map[string]any{}, nil, true); code != 200 {
			t.Fatalf("handoff revoke: %d", code)
		}
		if code, _ := send("GET", revoked, nil, bearer, false); code != 404 {
			t.Fatalf("revoked handoff delivered: %d", code)
		}
		expired := create()
		server.Connectors.Now = func() time.Time { return time.Now().Add(6 * time.Minute) }
		if code, _ := send("GET", expired, nil, bearer, false); code != 404 {
			t.Fatalf("expired handoff delivered: %d", code)
		}
		server.Connectors.Now = nil

		source := p["bundle"].(map[string]any)["observations"].([]any)[0].(map[string]any)["evidence_id"].(string)
		draft := map[string]any{
			"incident_id": "inc-1", "handoff_id": strings.TrimPrefix(path, "/desktop/handoffs/"),
			"client_label": "Synthetic app", "limitations": []string{"Fixture evidence only."}, "proposed_steps": []any{},
		}
		draft["claims"] = []any{map[string]any{"claim": "One retained gateway record was blocked.", "kind": "observation", "source_ids": []string{source}}}
		submit := func(headers map[string]string, ownerSession bool) (int, map[string]any) {
			t.Helper()
			return send("POST", "/desktop/drafts", draft, headers, ownerSession)
		}
		primary := map[string]string{"Authorization": bearer["Authorization"], "Idempotency-Key": "fixture-draft-key-001"}
		if code, _ := submit(primary, false); code != 403 {
			t.Fatalf("draft accepted without distinct consent: %d", code)
		}
		in["allow_analysis_draft"] = true
		allowed := create()
		draft["handoff_id"] = strings.TrimPrefix(allowed, "/desktop/handoffs/")
		if code, _ := submit(primary, false); code != 403 {
			t.Fatalf("draft accepted before handoff delivery: %d", code)
		}
		if code, _ := send("GET", allowed, nil, bearer, false); code != 200 {
			t.Fatalf("draft handoff delivery: %d", code)
		}
		if code, _ := submit(nil, true); code != 403 {
			t.Fatalf("owner impersonated connector: %d", code)
		}
		wrong := map[string]string{"Authorization": "Bearer " + other["token"].(string), "Idempotency-Key": "fixture-draft-key-001"}
		if code, _ := submit(wrong, false); code != 403 {
			t.Fatalf("wrong connector submitted draft: %d", code)
		}
		draft["claims"] = []any{map[string]any{"claim": "One retained record.", "kind": "observation", "source_ids": []string{"sha256:" + strings.Repeat("f", 64)}}}
		if code, v := submit(primary, false); code != 400 || v["error"].(map[string]any)["code"] != "SOURCE_ID_INVALID" {
			t.Fatalf("foreign evidence accepted: %d", code)
		}
		draft["claims"] = []any{map[string]any{"claim": "One retained gateway record was blocked.", "kind": "observation", "source_ids": []string{source}}}
		code, created := submit(primary, false)
		if code != 201 || created["state"] != "unverified" {
			t.Fatalf("draft submission: %d %v", code, created)
		}
		did := created["draft_id"].(string)
		if code, retry := submit(primary, false); code != 200 || retry["draft_id"] != did {
			t.Fatalf("draft replay: %d", code)
		}
		draft["client_label"] = "Changed label"
		if code, _ := submit(primary, false); code != 409 {
			t.Fatalf("changed replay: %d", code)
		}
		draft["client_label"] = "Synthetic app"
		if code, _ := submit(map[string]string{"Authorization": bearer["Authorization"], "Idempotency-Key": "fixture-draft-key-002"}, false); code != 409 {
			t.Fatalf("second draft per handoff: %d", code)
		}
		statusPath := "/desktop/drafts/" + did
		if code, v := send("GET", statusPath, nil, bearer, false); code != 200 || len(v) != 2 || v["state"] != "unverified" {
			t.Fatalf("draft status scope: %d", code)
		}
		if code, _ := send("GET", statusPath, nil, wrong, false); code != 404 {
			t.Fatalf("wrong connector read draft status: %d", code)
		}
		if code, _ := send("GET", "/desktop/drafts?incident_id=inc-1", nil, bearer, false); code != 403 {
			t.Fatalf("connector enumerated drafts: %d", code)
		}
		code, ownerDrafts := send("GET", "/desktop/drafts?incident_id=inc-1", nil, nil, true)
		if code != 200 || len(ownerDrafts["items"].([]any)) != 1 {
			t.Fatalf("owner review list: %d", code)
		}
		if code, _ := send("POST", statusPath+"/dismiss", map[string]any{}, bearer, true); code != 403 {
			t.Fatalf("connector dismissed draft: %d", code)
		}
		if code, _ := send("POST", statusPath+"/dismiss", map[string]any{}, nil, true); code != 200 {
			t.Fatalf("owner dismissal: %d", code)
		}
		if code, v := send("GET", statusPath, nil, bearer, false); code != 200 || v["state"] != "dismissed" {
			t.Fatalf("dismissal not observable: %d", code)
		}
		if code, _ := send("POST", allowed+"/revoke", map[string]any{}, nil, true); code != 200 {
			t.Fatalf("draft handoff withdrawal: %d", code)
		}
		if code, _ := submit(primary, false); code != 403 {
			t.Fatalf("withdrawn handoff replayed: %d", code)
		}
	})
	if code, _ := send("POST", "/connectors/"+id+"/revoke", map[string]any{}, nil, true); code != 200 {
		t.Fatal("revoke", code)
	}
	if code, _ := send("GET", "/sites", nil, bearer, false); code != 401 {
		t.Fatal("revoked credential still works", code)
	}
	if code, _ := send("POST", "/connectors/"+id+"/revoke", map[string]any{}, nil, true); code != 409 {
		t.Fatal("double revoke", code)
	}
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}

func TestAdvisoryCallsDoNotHoldTheMutationLock(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	a.Enroll(a.Bootstrap, "a sufficiently long test passphrase")
	login := httptest.NewRecorder()
	csrf, _ := a.Login(login, httptest.NewRequest("POST", "http://localhost", nil), "a sufficiently long test passphrase")
	cookie := login.Result().Cookies()[0]
	server := &Server{S: s, A: a, Q: &research.Queue{S: s}, Assets: t.TempDir(), Connectors: &connector.Registry{S: s}}
	h := server.Handler()
	server.mutations.Lock() // a long state change is in progress
	defer server.mutations.Unlock()
	send := func(path string) int {
		req := httptest.NewRequest("POST", "http://localhost/api/v1"+path, bytes.NewReader([]byte(`{"finding":{"category":"secret_candidate","path":"a.txt"},"draft_patch":false}`)))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if c := send("/findings/remediation"); c != 200 {
		t.Fatal("advisory call blocked by mutation lock", c)
	}
	if c := send("/connectors"); c != 429 {
		t.Fatal("state change ran while another held the lock", c)
	}
}
