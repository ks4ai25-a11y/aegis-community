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
	"testing"
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
