//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReconcilerHTTPRequiresSeparateRoleAndExactContextShape(t *testing.T) {
	s, worker, input := fixture(t)
	engine, registry, policy := domain.Hash([]byte("engine")), domain.Hash([]byte("registry")), domain.Hash([]byte("policy"))
	if _, err := s.Q.BindEngine("owner-a", engine, registry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Q.BindJournal("owner-a", domain.Hash([]byte("journal root")), domain.Hash([]byte("journal namespace"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Q.BindBroker("owner-a", worker.Worker.ID); err != nil {
		t.Fatal(err)
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(parent, 0700) != nil {
		t.Fatal("private fixture unavailable")
	}
	authorizerPath := filepath.Join(parent, "authorizer.token")
	authorizer, err := s.Auth.EnrollAuthorizerFile("owner-a", "authorizer-a", 10, engine, registry, policy, authorizerPath)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.Q.BindMutationAuthorizer("owner-a", authorizer.ID, domain.Hash([]byte("physical registry namespace")))
	if err != nil {
		t.Fatal(err)
	}
	reconcilerPath := filepath.Join(parent, "reconciler.token")
	v, err := s.Auth.EnrollReconcilerFile("owner-a", "reconciler-a", 10, binding.Digest, reconcilerPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(reconcilerPath)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	observerPath := filepath.Join(parent, "observer.token")
	if _, err = s.Auth.EnrollVerifierFile("owner-a", "observer-a", 10, engine, registry, observerPath); err != nil {
		t.Fatal(err)
	}
	observer, _ := os.ReadFile(observerPath)
	authorizerToken, _ := os.ReadFile(authorizerPath)
	h := s.Handler()
	identity := call(t, h, token, "reconciler/identity", "{}", 200)
	if identity["role"] != scanevidence.ScannerReconcilerRole || identity["binding_digest"] != v.Binding {
		t.Fatal("reconciler identity lost scope")
	}
	for _, other := range []string{worker.Token, strings.TrimSpace(string(observer)), strings.TrimSpace(string(authorizerToken)), ""} {
		call(t, h, other, "reconciler/identity", "{}", 401)
	}
	for _, operation := range []string{"identity", "claim", "verifier/identity", "authorizer/identity", "authorizer/admit", "authorizer/complete"} {
		call(t, h, token, operation, "{}", 401)
	}
	for _, operation := range []string{"release", "reset", "admit", "complete"} {
		call(t, h, token, "reconciler/"+operation, "{}", 404)
	}
	job, err := s.Q.Enqueue("owner-a", "reconciliation-context-http", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Q.Claim(worker.Worker.ID, "owner-a"); err != nil {
		t.Fatal(err)
	}
	var generation string
	if err = s.Q.S.DB.QueryRow("SELECT id FROM scanner_allocation_generations WHERE job=?", job.ID).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	req := scanevidence.ReconciliationRequest{Job: job.ID, Generation: generation, Challenge: strings.Repeat("a", 32)}
	body, _ := json.Marshal(req)
	call(t, h, token, "reconciler/context", string(body), 409)
	if err = s.Q.Cancel("owner-a", job.ID); err != nil {
		t.Fatal(err)
	}
	out := call(t, h, token, "reconciler/context", string(body), 200)
	wire, _ := json.Marshal(out)
	var snapshot scanevidence.ReconciliationSnapshot
	if json.Unmarshal(wire, &snapshot) != nil || !scanevidence.ValidateReconciliationSnapshot(snapshot, v, req, time.Now()) {
		t.Fatal("closed context failed scope validation")
	}
	for _, bad := range []string{"null", "{}", string(body) + "{}", strings.TrimSuffix(string(body), "}") + `,"tool_ids":["bandit"]}`, strings.Replace(string(body), `"job_id"`, `"Job_ID"`, 1), strings.TrimSuffix(string(body), "}") + `,"job_id":"` + job.ID + `"}`, strings.Replace(string(body), `"generation_id":"`+generation+`"`, `"generation_id":null`, 1)} {
		call(t, h, token, "reconciler/context", bad, 400)
	}
	if err = s.Auth.RevokeReconciler(v.Owner, v.ID); err != nil {
		t.Fatal(err)
	}
	call(t, h, token, "reconciler/context", string(body), 401)
}
