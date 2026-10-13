package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/research"
	"aegis.local/controller/internal/scope"
	"aegis.local/controller/internal/store"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestScopedJobHTTPAndIDOR(t *testing.T) {
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
	q := &research.Queue{S: s}
	server := &Server{S: s, A: a, Q: q, Assets: t.TempDir()}
	handler := server.Handler()
	call := func(method, path string, body any, expected int, extra map[string]string) map[string]any {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, "http://localhost/api/v1"+path, bytes.NewReader(b))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != expected {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	call("POST", "/scope-grants", map[string]any{"app_id": "app_demo", "mode": "test_lab", "fixture_id": scope.Fixture, "lifetime_minutes": 10, "target_url": "http://169.254.169.254"}, 400, nil)
	grant := call("POST", "/scope-grants", map[string]any{"app_id": "app_demo", "mode": "test_lab", "fixture_id": scope.Fixture, "lifetime_minutes": 10}, 201, nil)
	id := grant["grant"].(map[string]any)["scope_grant_id"].(string)
	digest := grant["approved_digest"].(string)
	call("POST", "/scope-grants/"+id+"/approve", map[string]any{"approved_digest": "different", "acknowledge_test_scope": true}, 409, nil)
	call("POST", "/scope-grants/"+id+"/approve", map[string]any{"approved_digest": digest, "acknowledge_test_scope": true}, 200, nil)
	_, p, e := s.Active()
	if e != nil {
		t.Fatal(e)
	}
	input := research.Input{"1.0", "app_demo", id, digest, scope.Fixture, p}
	headers := map[string]string{"Idempotency-Key": "http-test-key-001"}
	first := call("POST", "/verifications", input, 202, headers)
	second := call("POST", "/verifications", input, 202, headers)
	if first["job_id"] != second["job_id"] {
		t.Fatal("HTTP retry duplicated job")
	}
	call("POST", "/scope-grants/"+id+"/revoke", map[string]any{}, 200, nil)
	job := call("GET", "/verifications/"+first["job_id"].(string), nil, 200, nil)
	if job["state"] != "cancelled" {
		t.Fatal(job)
	}
	// Simulate a second authenticated owner to test future-proof resource ownership.
	secondOwner := domain.ID()
	s.DB.Exec("INSERT INTO owners VALUES(?,'fixture-only',?)", secondOwner, domain.Now())
	token := auth.Token()
	hash := domain.Hash([]byte(token))
	s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,strftime('%s','now'),strftime('%s','now'),strftime('%s','now')+3600)", hash, secondOwner, domain.Hash([]byte(csrf)))
	cookie = &http.Cookie{Name: "aegis_session", Value: token}
	call("GET", "/verifications/"+first["job_id"].(string), nil, 404, nil)
	call("GET", "/scope-grants/"+id, nil, 404, nil)
	// A known report digest alone never grants read access.
	report := domain.Report{Schema: "1.0", ID: domain.ID(), Overall: "INCONCLUSIVE"}
	report.Digest = domain.Digest(report)
	var owner string
	s.DB.QueryRow("SELECT id FROM owners WHERE id<>?", secondOwner).Scan(&owner)
	if e = s.SaveReport(owner, report); e != nil {
		t.Fatal(e)
	}
	call("GET", "/verify/reports/"+report.Digest, nil, 404, nil)
}
