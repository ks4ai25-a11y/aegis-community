// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package scantransport

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func verifierHTTPFixture(t *testing.T) (*Server, string, string, string, string, scanevidence.VerifierIdentity) {
	t.Helper()
	s, worker, body := launchBody(t)
	got := call(t, s.Handler(), worker, "launch", body, 200)
	b, _ := json.Marshal(got["record"])
	var record scanevidence.LaunchRecord
	if json.Unmarshal(b, &record) != nil {
		t.Fatal("launch fixture")
	}
	p, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(p, 0700)
	path := filepath.Join(p, "verifier.token")
	v, e := s.Auth.EnrollVerifierFile(record.Document.Owner, "verifier-a", 10, record.Document.Plan.Engine, record.Document.Plan.Registry, path)
	if e != nil {
		t.Fatal(e)
	}
	token, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return s, worker, strings.TrimSpace(string(token)), record.Document.Job, path, v
}
func TestVerifierHTTPReadsContextAndCannotAcquireWorkerAuthority(t *testing.T) {
	s, worker, token, job, path, v := verifierHTTPFixture(t)
	h := s.Handler()
	identity := call(t, h, token, "verifier/identity", "{}", 200)
	if identity["role"] != scanevidence.CleanupObserverRole || identity["verifier_id"] != v.ID {
		t.Fatal(identity)
	}
	out := call(t, h, token, "verifier/context", `{"job_id":"`+job+`"}`, 200)
	wire, _ := json.Marshal(out)
	var record scanevidence.CleanupContextRecord
	if json.Unmarshal(wire, &record) != nil || scanevidence.ValidateCleanupContext(record, v.Owner, v.ID, job, v.Engine, v.Registry, s.Q.LockDigest) != nil {
		t.Fatal("context lost binding")
	}
	if record.Document.CleanupConfirmed || record.Document.LeasesExcluded || record.Document.LateStartExcluded || !record.Document.MetadataOnly || strings.Contains(string(wire), token) || strings.Contains(string(wire), worker) {
		t.Fatal("context contains capability or cleanup proof")
	}
	for _, operation := range []string{"identity", "claim", "guard", "fail", "workspace", "launch", "receipt", "finish"} {
		call(t, h, token, operation, "{}", 401)
	}
	for _, operation := range []string{"verifier/identity", "verifier/context"} {
		call(t, h, worker, operation, "{}", 401)
	}
	call(t, h, token, "verifier/release", "{}", 404)
	call(t, h, token, "verifier/context", `{"job_id":"`+domain.ID()+`"}`, 404)
	wrong, e := s.Auth.EnrollVerifierFile(v.Owner, "verifier-other-engine", 1, source.Hash([]byte("other engine")), v.Registry, filepath.Join(filepath.Dir(path), "other.token"))
	if e != nil {
		t.Fatal(e)
	}
	other, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "other.token"))
	call(t, h, strings.TrimSpace(string(other)), "verifier/context", `{"job_id":"`+job+`"}`, 404)
	if e = s.Auth.RevokeVerifier(wrong.Owner, wrong.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Auth.RevokeVerifier(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	call(t, h, token, "verifier/identity", "{}", 401)
	call(t, h, token, "verifier/context", `{"job_id":"`+job+`"}`, 401)
	var state string
	s.Q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "active" {
		t.Fatal("verifier operation changed worker admission")
	}
	if e = s.Q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestVerifierHTTPRefusesHostileFramingAndBody(t *testing.T) {
	s, _, token, job, _, _ := verifierHTTPFixture(t)
	h := s.Handler()
	for _, body := range []string{"null", `{}`, `{"Job_id":"` + job + `"}`, `{"job_id":"` + job + `","job_id":"` + job + `"}`, `{"job_id":"` + job + `","cleanup_confirmed":true}`, `{"job_id":null}`, `{"job_id":"` + job + `"} {}`, `{"job_id":"` + strings.Repeat("x", 8193) + `"}`} {
		call(t, h, token, "verifier/context", body, 400)
	}
	for _, kind := range []string{"origin", "cookie", "query", "force_query", "encoding", "duplicate_authorization", "duplicate_type", "get"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://unix/internal/v1/scanner/verifier/context", strings.NewReader(`{"job_id":"`+job+`"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+token)
			expected := 403
			switch kind {
			case "origin":
				r.Header.Set("Origin", "http://localhost")
			case "cookie":
				r.Header.Set("Cookie", "aegis_session=not-authority")
			case "query":
				r.URL.RawQuery = "job_id=" + job
			case "force_query":
				r.URL.ForceQuery = true
			case "encoding":
				r.Header.Set("Content-Encoding", "identity")
				expected = 400
			case "duplicate_authorization":
				r.Header.Add("Authorization", "Bearer "+token)
				expected = 401
			case "duplicate_type":
				r.Header.Add("Content-Type", "application/json")
				expected = 400
			case "get":
				r.Method = "GET"
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != expected || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(kind, w.Code)
			}
		})
	}
}
func TestVerifierProbeRequiresPrivateCredentialAndDistinctRole(t *testing.T) {
	s, worker, token, _, path, v := verifierHTTPFixture(t)
	dir, e := os.MkdirTemp("/tmp", "avp-")
	if e != nil {
		t.Fatal(e)
	}
	dir, _ = filepath.EvalSymlinks(dir)
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0700)
	socket := filepath.Join(dir, "worker.sock")
	listener, e := Listen(socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: s.Handler()}
	defer server.Close()
	go server.Serve(listener)
	got, e := ProbeVerifier(context.Background(), socket, path)
	if e != nil || got != v {
		t.Fatal(got, e)
	}
	if _, e = Probe(context.Background(), socket, path); e == nil {
		t.Fatal("verifier probed as worker")
	}
	workerPath := filepath.Join(filepath.Dir(path), "worker.token")
	os.WriteFile(workerPath, []byte(worker+"\n"), 0600)
	if _, e = ProbeVerifier(context.Background(), socket, workerPath); e == nil {
		t.Fatal("worker probed as verifier")
	}
	if e = os.Chmod(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = ProbeVerifier(context.Background(), socket, path); e == nil {
		t.Fatal("public parent accepted")
	}
	os.Chmod(filepath.Dir(path), 0700)
	if e = s.Auth.RevokeVerifier(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = ProbeVerifier(context.Background(), socket, path); e == nil {
		t.Fatal("revoked probe accepted")
	}
	if strings.Contains(got.Owner, token) {
		t.Fatal("unexpected credential output")
	}
}
