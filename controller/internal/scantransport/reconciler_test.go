//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
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
	for _, operation := range []string{"release", "reset", "admit", "complete", "cleanup"} {
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
	confirm := scanevidence.CleanupConfirmationRequest{Job: job.ID, Generation: generation, Membership: snapshot.MembershipHash, Engine: snapshot.Membership.Binding.Document.Engine, Namespace: snapshot.Membership.Binding.Document.Namespace, Absent: []scanevidence.CleanupAbsence{}}
	confirmBody, _ := json.Marshal(confirm)
	// The job is still running under cancellation, so nothing may be released.
	call(t, h, token, "reconciler/confirm", string(confirmBody), 409)
	for _, bad := range []string{"{}", strings.Replace(string(confirmBody), `"absent":[]`, `"absent":null`, 1), strings.Replace(string(confirmBody), `"absent":[]`, `"absent":[{"tool_id":"bandit","container":"x","engine_id":"","extra":1}]`, 1), strings.TrimSuffix(string(confirmBody), "}") + `,"dispatch_released":true}`} {
		call(t, h, token, "reconciler/confirm", bad, 400)
	}
	// Crash repair shares the reconciler role and fails closed on shape, scope
	// and an unfinished job; an authorizer may only read its own intents.
	b := snapshot.Membership.Binding
	repair := scanevidence.MutationRepairRequest{Job: job.ID, Generation: generation, Membership: snapshot.MembershipHash, Engine: b.Document.Engine, Namespace: b.Document.Namespace, Fence: scanevidence.RepairFence{Policy: scanevidence.AdmittedJournalSeal(b.Document.Policy, b.Digest), Quarantine: domain.Hash([]byte("q")), Activation: domain.Hash([]byte("a"))}, Resolutions: []scanevidence.MutationResolution{{Intent: domain.Hash([]byte("i")), Operation: "create", Outcome: scanevidence.RepairNotCreated, Evidence: domain.Hash([]byte("e"))}}}
	repairBody, _ := json.Marshal(repair)
	call(t, h, token, "reconciler/repair", string(repairBody), 409)
	call(t, h, strings.TrimSpace(string(authorizerToken)), "reconciler/repair", string(repairBody), 401)
	for _, bad := range []string{"{}", strings.Replace(string(repairBody), `"resolutions":[`, `"resolutions":null,"x":[`, 1), strings.Replace(string(repairBody), `"outcome":"not_created"`, `"outcome":"not_created","extra":1`, 1), strings.Replace(string(repairBody), `"activation_digest"`, `"activation"`, 1), strings.TrimSuffix(string(repairBody), "}") + `,"cleanup_release_authorized":true}`, strings.Replace(string(repairBody), `"outcome":"not_created"`, `"outcome":"absent"`, 1)} {
		call(t, h, token, "reconciler/repair", bad, 400)
	}
	read, _ := json.Marshal(scanevidence.AuthorizerIntentRequest{Generation: generation, Intent: domain.Hash([]byte("never admitted"))})
	got := call(t, h, strings.TrimSpace(string(authorizerToken)), "authorizer/intent", string(read), 200)
	if got["found"] != false || got["intent"] != nil {
		t.Fatal("never-admitted intent reported", got)
	}
	call(t, h, token, "authorizer/intent", string(read), 401)
	call(t, h, strings.TrimSpace(string(authorizerToken)), "authorizer/intent", strings.TrimSuffix(string(read), "}")+`,"state":"repaired"}`, 400)
	if err = s.Auth.RevokeReconciler(v.Owner, v.ID); err != nil {
		t.Fatal(err)
	}
	call(t, h, token, "reconciler/context", string(body), 401)
	call(t, h, token, "reconciler/confirm", string(confirmBody), 401)
	call(t, h, token, "reconciler/repair", string(repairBody), 401)
}
