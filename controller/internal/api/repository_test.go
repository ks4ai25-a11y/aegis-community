package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/store"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryHTTPRejectsPathsAndUnknownFields(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "repo-api.db"))
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
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(path, "fixture"), 0700)
	os.WriteFile(filepath.Join(path, "fixture", "source.py"), []byte("static"), 0600)
	registry, e := repository.Open(s, path)
	if e != nil {
		t.Fatal(e)
	}
	defer registry.Root.Close()
	server := &Server{S: s, A: a, R: registry, Assets: t.TempDir()}
	handler := server.Handler()
	call := func(method, path string, body any, status int) map[string]any {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "http://localhost/api/v1"+path, bytes.NewReader(b))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		out := map[string]any{}
		if e = json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	call("POST", "/repos", map[string]any{"app_id": "app_demo", "asset_id": "fixture", "acknowledge_read_only": true, "path": "/etc"}, 400)
	call("POST", "/repos", map[string]any{"app_id": "app_demo", "asset_id": "../etc", "acknowledge_read_only": true}, 400)
	call("POST", "/repos", map[string]any{"app_id": "app_demo", "asset_id": "fixture", "acknowledge_read_only": false}, 400)
	repo := call("POST", "/repos", map[string]any{"app_id": "app_demo", "asset_id": "fixture", "acknowledge_read_only": true}, 201)
	id := repo["repository_id"].(string)
	call("GET", "/repos/"+id, nil, 200)
	m := call("GET", "/repos/"+id+"/map", nil, 200)
	if m["content_digest"] != repo["map_digest"] {
		t.Fatal("map identity differs")
	}
	call("GET", "/repos", nil, 200)
	call("GET", "/repos/assets", nil, 200)
	call("GET", "/repos/unknown/map", nil, 404)
	call("GET", "/repos/"+id+"/rescan", nil, 503)
	server.Scans = &scanqueue.Queue{S: s, LockDigest: "sha256:" + strings.Repeat("a", 64)}
	if p := call("GET", "/repos/"+id+"/rescan", nil, 200); p["enabled"] != false {
		t.Fatal(p)
	}
	call("POST", "/repos/"+id+"/rescan", map[string]any{"enabled": true, "tool_ids": []string{"shell"}, "tool_timeout_seconds": 30}, 400)
	call("POST", "/repos/"+id+"/rescan", map[string]any{"enabled": true, "tool_ids": []string{"bandit"}, "tool_timeout_seconds": 30, "path": "/etc"}, 400)
	if p := call("POST", "/repos/"+id+"/rescan", map[string]any{"enabled": true, "tool_ids": []string{"bandit"}, "tool_timeout_seconds": 30}, 200); p["enabled"] != true || p["baseline_map_digest"] != repo["map_digest"] {
		t.Fatal(p)
	}
	call("GET", "/repos/unknown/rescan", nil, 404)
	plan := call("POST", "/repos/"+id+"/research-plan", map[string]any{"use_model": false}, 200)
	if plan["map_digest"] != repo["map_digest"] || plan["planner"] != "deterministic" {
		t.Fatal(plan)
	}
	call("POST", "/repos/"+id+"/research-plan", map[string]any{"use_model": false, "tools": []string{"run_shell_anywhere"}}, 400)
	call("POST", "/repos/unknown/research-plan", map[string]any{}, 404)
}
