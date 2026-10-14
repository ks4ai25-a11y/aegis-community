// SPDX-License-Identifier: Apache-2.0
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnerScannerHTTPAuthorityAndAdmission(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	password := "a sufficiently long test passphrase"
	if e = a.Enroll(a.Bootstrap, password); e != nil {
		t.Fatal(e)
	}
	login := httptest.NewRecorder()
	csrf, e := a.Login(login, httptest.NewRequest("POST", "http://localhost", nil), password)
	if e != nil {
		t.Fatal(e)
	}
	cookie := login.Result().Cookies()[0]
	var owner string
	s.DB.QueryRow("SELECT id FROM owners").Scan(&owner)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(root, "fixture"), 0700)
	os.WriteFile(filepath.Join(root, "fixture", "app.py"), []byte("static only"), 0600)
	repos, e := repository.Open(s, root)
	if e != nil {
		t.Fatal(e)
	}
	defer repos.Root.Close()
	repo, e := repos.Connect(owner, "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	guards, _ := scanevidence.NewGuardSet(domain.Hash([]byte("test guard")), domain.Hash([]byte("test arm64 guard")))
	q := &scanqueue.Queue{S: s, LockDigest: domain.Hash([]byte("test lock")), Guards: guards}
	server := &Server{S: s, A: a, Scans: q, Assets: t.TempDir()}
	handler := server.Handler()
	call := func(method, path, body string, expected int, headers map[string]string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, "http://localhost/api/v1"+path, strings.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != expected {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("scanner response cacheable")
		}
		var out map[string]any
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{"lease_token", "token_hash", "credential", "registry_digest", "engine_digest"} {
			if bytes.Contains(w.Body.Bytes(), []byte(secret)) {
				t.Fatal("private authority exposed", secret)
			}
		}
		return out
	}
	in := scanqueue.Input{Schema: "1.0", App: "app_demo", Repository: repo.ID, MapDigest: repo.MapDigest, Mode: "repo_offline", Tools: []string{"bandit"}, Duration: 30}
	b, _ := json.Marshal(in)
	body := string(b)
	key := map[string]string{"Idempotency-Key": "http-scan-key-001"}
	call("POST", "/scans", body, 401, map[string]string{"X-CSRF-Token": ""})
	call("POST", "/scans", body, 403, map[string]string{"Origin": "https://other.invalid"})
	call("POST", "/scans", body, 400, nil)
	call("POST", "/scans", `{"owner_id":"other"}`, 400, key)
	call("POST", "/scans", `{"schema_version":"1.0","schema_version":"1.0"}`, 400, key)
	j := call("POST", "/scans", body, 202, key)
	id := j["job_id"].(string)
	retry := call("POST", "/scans", body, 202, key)
	if retry["job_id"] != id {
		t.Fatal("retry duplicated scan")
	}
	call("POST", "/scans", strings.Replace(body, `"tool_timeout_seconds":30`, `"tool_timeout_seconds":31`, 1), 409, key)
	status := call("GET", "/scans/"+id, "", 200, nil)
	if status["execution_admission"] != "not_claimed" {
		t.Fatal(status)
	}
	call("GET", "/scans/"+id+"/result", "", 409, nil)
	call("GET", "/findings?job_id="+id, "", 409, nil)
	call("GET", "/findings?job_id="+id+"&limit=21", "", 400, nil)
	call("GET", "/findings?job_id="+id+"&job_id=other", "", 400, nil)
	list := call("GET", "/scans", "", 200, nil)
	if len(list["items"].([]any)) != 1 {
		t.Fatal(list)
	}
	if _, e = s.DB.Exec("INSERT INTO scanner_workers VALUES(?, ?, ?, 'active', ?, ?)", "http-worker", owner, domain.Hash([]byte("fixture credential")), time.Now().Add(time.Hour).Unix(), domain.Now()); e != nil {
		t.Fatal(e)
	}
	l, e := q.Claim("http-worker", owner)
	if e != nil {
		t.Fatal(e)
	}
	status = call("GET", "/scans/"+id, "", 200, nil)
	if status["execution_admission"] != "active" {
		t.Fatal(status)
	}
	call("POST", "/scans/"+id+"/cancel", `{"cleanup_confirmed":true}`, 400, nil)
	call("POST", "/scans/"+id+"/cancel", `null`, 400, nil)
	status = call("POST", "/scans/"+id+"/cancel", `{}`, 200, nil)
	if status["execution_admission"] != "active" || !status["job"].(map[string]any)["cancel_requested"].(bool) {
		t.Fatal(status)
	}
	q.Now = func() time.Time { return time.Now().Add(time.Minute) }
	if e = q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	status = call("GET", "/scans/"+id, "", 200, nil)
	if status["execution_admission"] != "cleanup_required" || status["job"].(map[string]any)["state"] != "cancelled" {
		t.Fatal(status)
	}
	_ = l
	second := domain.ID()
	if _, e = s.DB.Exec("INSERT INTO owners VALUES(?,'test',?)", second, domain.Now()); e != nil {
		t.Fatal(e)
	}
	token := auth.Token()
	s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,strftime('%s','now'),strftime('%s','now'),strftime('%s','now')+3600)", domain.Hash([]byte(token)), second, domain.Hash([]byte(csrf)))
	cookie = &http.Cookie{Name: "aegis_session", Value: token}
	for _, suffix := range []string{"", "/result", "/cancel"} {
		method, body := "GET", ""
		if suffix == "/cancel" {
			method, body = "POST", "{}"
		}
		call(method, "/scans/"+id+suffix, body, 404, nil)
	}
	call("GET", "/findings?job_id="+id, "", 404, nil)
	call("POST", "/scans", body, 404, key)
	list = call("GET", "/scans", "", 200, nil)
	if len(list["items"].([]any)) != 0 {
		t.Fatal("cross-owner list", list)
	}
	server.Scans = nil
	call("GET", "/scans", "", 503, nil)
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
