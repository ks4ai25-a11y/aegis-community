// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package scantransport

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorizerRoleDoesNotInheritWorkerObserverOrReleaseAuthority(t *testing.T) {
	s, worker, observer, _, path, v := verifierHTTPFixture(t)
	credential := filepath.Join(filepath.Dir(path), "authorizer.credential")
	a, e := s.Auth.EnrollAuthorizerFile(v.Owner, "authorizer-a", 1, v.Engine, v.Registry, domain.Hash([]byte("policy")), credential)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(credential)
	token := strings.TrimSpace(string(b))
	h := s.Handler()
	out := call(t, h, token, "authorizer/identity", "{}", 200)
	raw, _ := json.Marshal(out)
	var got scanevidence.AuthorizerIdentity
	if json.Unmarshal(raw, &got) != nil || got != a {
		t.Fatal("identity scope changed")
	}
	for _, role := range []string{worker, observer, ""} {
		call(t, h, role, "authorizer/identity", "{}", 401)
	}
	for _, operation := range []string{"identity", "claim", "renew", "finish", "verifier/identity", "verifier/context"} {
		call(t, h, token, operation, "{}", 401)
	}
	for _, operation := range []string{"release", "reset"} {
		call(t, h, token, "authorizer/"+operation, "{}", 404)
	}
	for _, operation := range []string{"admit", "complete", "launch"} {
		call(t, h, token, "authorizer/"+operation, "{}", 400)
	}
	for _, body := range []string{"null", `{"role":"scanner-engine-authorizer"}`, `{} {}`, `{"cleanup_confirmed":true}`} {
		call(t, h, token, "authorizer/identity", body, 400)
	}
	for _, kind := range []string{"origin", "cookie", "query", "raw-path", "encoding", "duplicate-auth", "duplicate-type", "get"} {
		r := httptest.NewRequest("POST", "http://unix/internal/v1/scanner/authorizer/identity", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		expected := 403
		switch kind {
		case "origin":
			r.Header.Set("Origin", "http://localhost")
		case "cookie":
			r.Header.Set("Cookie", "aegis_session=not-authority")
		case "query":
			r.URL.RawQuery = "unexpected=1"
		case "raw-path":
			r.URL.RawPath = "/internal/v1/scanner/authorizer/%69dentity"
		case "encoding":
			r.Header.Set("Content-Encoding", "gzip")
			expected = 400
		case "duplicate-auth":
			r.Header.Add("Authorization", "Bearer "+token)
			expected = 401
		case "duplicate-type":
			r.Header.Add("Content-Type", "application/json")
			expected = 400
		case "get":
			r.Method = "GET"
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		if response.Code != expected {
			t.Fatal("hostile authorizer framing accepted", kind, response.Code)
		}
	}
	if e = s.Auth.RevokeAuthorizer(v.Owner, a.ID); e != nil {
		t.Fatal(e)
	}
	call(t, h, token, "authorizer/identity", "{}", 401)
	var count int
	if e = s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&count); e != nil || count != 1 {
		t.Fatal("role enrollment/revocation changed dispatch")
	}
	if e = s.Q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}

func TestAuthorizerPrivateUnixProbeAndRevocation(t *testing.T) {
	s, _, _, _, path, v := verifierHTTPFixture(t)
	credential := filepath.Join(filepath.Dir(path), "authorizer.credential")
	a, e := s.Auth.EnrollAuthorizerFile(v.Owner, "authorizer-a", 1, v.Engine, v.Registry, domain.Hash([]byte("policy")), credential)
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("/tmp", "aap-")
	if e != nil {
		t.Fatal(e)
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	listener, e := Listen(filepath.Join(dir, "authorizer.sock"))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(s.Handler())
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	got, e := ProbeAuthorizer(context.Background(), listener.Addr().String(), credential)
	if e != nil || got != a {
		t.Fatal("private probe failed", e)
	}
	if _, e = ProbeVerifier(context.Background(), listener.Addr().String(), credential); e == nil {
		t.Fatal("authorizer accepted as observer")
	}
	if _, e = Probe(context.Background(), listener.Addr().String(), credential); e == nil {
		t.Fatal("authorizer accepted as worker")
	}
	if e = s.Auth.RevokeAuthorizer(v.Owner, a.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = ProbeAuthorizer(context.Background(), listener.Addr().String(), credential); e == nil {
		t.Fatal("revoked authorizer probe accepted")
	}
}

func TestAuthorizerMutationRequestRequiresExactCompleteShape(t *testing.T) {
	s, _, _, _, path, v := verifierHTTPFixture(t)
	credential := filepath.Join(filepath.Dir(path), "mutation-authorizer")
	if _, e := s.Auth.EnrollAuthorizerFile(v.Owner, "mutation-authorizer", 1, v.Engine, v.Registry, domain.Hash([]byte("policy")), credential); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(credential)
	if e != nil {
		t.Fatal(e)
	}
	token := strings.TrimSpace(string(raw))
	valid := scanevidence.MutationRequest{Generation: strings.Repeat("a", 64), Job: domain.ID(), Tool: "bandit", Operation: "create", Launch: domain.Hash([]byte("launch")), Descriptor: domain.Hash([]byte("descriptor"))}
	body, _ := json.Marshal(valid)
	for _, kind := range []string{"missing", "alias", "duplicate", "null", "unknown", "trailing", "huge", "wrong-operation"} {
		hostile := string(body)
		switch kind {
		case "missing":
			hostile = strings.Replace(hostile, `,"target_engine_id":""`, "", 1)
		case "alias":
			hostile = strings.Replace(hostile, `"generation_id"`, `"Generation_ID"`, 1)
		case "duplicate":
			hostile = strings.Replace(hostile, `"tool_id":"bandit"`, `"tool_id":"bandit","tool_id":"bandit"`, 1)
		case "null":
			hostile = strings.Replace(hostile, `"target_engine_id":""`, `"target_engine_id":null`, 1)
		case "unknown":
			hostile = strings.TrimSuffix(hostile, "}") + `,"cleanup_confirmed":true}`
		case "trailing":
			hostile += "{}"
		case "huge":
			hostile = strings.Repeat(" ", 8193)
		case "wrong-operation":
			hostile = strings.Replace(hostile, `"operation":"create"`, `"operation":"restart"`, 1)
		}
		call(t, s.Handler(), token, "authorizer/admit", hostile, 400)
	}
	var n int
	if e = s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 0 {
		t.Fatal("hostile framing created an obligation", e)
	}
}
