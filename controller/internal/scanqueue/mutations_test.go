// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mutationFixture(t *testing.T) (*Queue, Lease, scanevidence.AuthorizerIdentity, MutationRequest, MutationBinding) {
	t.Helper()
	q, in, _ := fixture(t)
	_, journal := provisionJournalFixture(t, q)
	if _, e := q.BindBroker("owner-a", "trusted-worker"); e != nil {
		t.Fatal(e)
	}
	auth := &scannerauth.Registry{S: q.S, Now: q.Now}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	v, e := auth.EnrollAuthorizerFile("owner-a", "authorizer-a", 60, domain.Hash([]byte("engine")), domain.Hash([]byte("registry")), domain.Hash([]byte("policy")), filepath.Join(dir, "authorizer.credential"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := q.BindMutationAuthorizer(v.Owner, v.ID, domain.Hash([]byte("physical namespace")))
	if e != nil {
		t.Fatal(e)
	}
	in.Tools = []string{"bandit"}
	q.Pins = map[string]Pin{"bandit": {"1.9.4", domain.Hash([]byte("image"))}}
	l := enqueueClaim(t, q, in)
	manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range manifest.Files {
		manifest.Bytes += f.Size
	}
	manifest.Digest = domain.Digest(manifest)
	p := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: v.Engine, Registry: v.Registry, Workspace: "run-" + strings.Repeat("a", 32), Snapshot: manifest.Digest, Guard: q.Guards.AMD64, Architecture: "amd64", JournalBinding: journal.Digest, JournalNamespace: journal.Document.Namespace}
	reserveLaunchWorkspace(t, q, l, p)
	launch, e := q.RegisterLaunch(l, p)
	if e != nil {
		t.Fatal(e)
	}
	g, e := q.GenerationForAuthorizer(context.Background(), v, l.Job.ID)
	if e != nil {
		t.Fatal(e)
	}
	return q, l, v, MutationRequest{Generation: g.ID, Job: l.Job.ID, Tool: "bandit", Operation: "create", Launch: launch.Digest, Descriptor: domain.Hash([]byte("native create descriptor"))}, b
}
func mustAdmit(t *testing.T, q *Queue, v scanevidence.AuthorizerIdentity, r MutationRequest) MutationIntent {
	t.Helper()
	a, e := q.AdmitMutation(context.Background(), v, r)
	if e != nil || a.Replay {
		t.Fatal("new obligation not admitted", e)
	}
	return a.Intent
}
func mustComplete(t *testing.T, q *Queue, v scanevidence.AuthorizerIdentity, m MutationIntent) MutationCompletion {
	t.Helper()
	status := 204
	id := m.Request.EngineID
	if m.Request.Operation == "create" {
		status = 201
		id = strings.Repeat("c", 64)
	}
	c := MutationCompletion{Intent: m.ID, Generation: m.Request.Generation, Status: status, EngineID: id, Response: domain.Hash([]byte("native response " + m.Request.Operation))}
	if _, e := q.CompleteMutation(context.Background(), v, c); e != nil {
		t.Fatal(e)
	}
	return c
}
func TestMutationLifecycleRetainsObligationsAndNeverReleasesSlot(t *testing.T) {
	q, l, v, r, _ := mutationFixture(t)
	created := mustAdmit(t, q, v, r)
	var pending int
	if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents WHERE state='pending'").Scan(&pending); e != nil || pending != 1 {
		t.Fatal("admission was not durable", e)
	}
	a, e := q.AdmitMutation(context.Background(), v, r)
	if e != nil || !a.Replay || a.Intent != created {
		t.Fatal("admission replay changed identity", e)
	}
	bad := r
	bad.Descriptor = domain.Hash([]byte("changed"))
	if _, e = q.AdmitMutation(context.Background(), v, bad); e == nil {
		t.Fatal("changed descriptor replay accepted")
	}
	start := r
	start.Operation = "start"
	start.EngineID = strings.Repeat("c", 64)
	start.Descriptor = domain.Hash([]byte("start"))
	if _, e = q.AdmitMutation(context.Background(), v, start); e == nil {
		t.Fatal("start passed unresolved create")
	}
	completion := mustComplete(t, q, v, created)
	if _, e = q.CompleteMutation(context.Background(), v, completion); e != nil {
		t.Fatal("completion replay refused", e)
	}
	badCompletion := completion
	badCompletion.Response = domain.Hash([]byte("changed response"))
	if _, e = q.CompleteMutation(context.Background(), v, badCompletion); e == nil {
		t.Fatal("completion overwritten")
	}
	started := mustAdmit(t, q, v, start)
	remove := start
	remove.Operation = "remove"
	remove.Descriptor = domain.Hash([]byte("remove"))
	if _, e = q.AdmitMutation(context.Background(), v, remove); e == nil {
		t.Fatal("cleanup passed unresolved start")
	}
	mustComplete(t, q, v, started)
	if e = q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = q.AdmitMutation(context.Background(), v, start); e == nil {
		t.Fatal("late start replay crossed closure")
	}
	removed := mustAdmit(t, q, v, remove)
	mustComplete(t, q, v, removed)
	if e = q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents WHERE state='pending'").Scan(&pending); e != nil || pending != 0 {
		t.Fatal(e)
	}
	var state string
	if e = q.S.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE job=?", l.Job.ID).Scan(&state); e != nil || state != "closed" {
		t.Fatal("generation did not close", e)
	}
	if _, e = q.S.DB.Exec("DELETE FROM scanner_dispatch WHERE job=?", l.Job.ID); e == nil {
		t.Fatal("settled ledger freed unverified slot")
	}
	if _, e = q.Claim("trusted-worker", l.Job.Owner); e != ErrCleanup {
		t.Fatal("second claim escaped cleanup hold", e)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestMutationAdmissionRefusesWithdrawnOrChangedAuthorityWithoutObligations(t *testing.T) {
	for _, kind := range []string{"wrong-role", "wrong-authorizer", "wrong-owner", "wrong-engine", "wrong-registry", "wrong-policy", "wrong-generation", "wrong-launch", "wrong-tool", "unknown-operation", "cancel", "terminal", "held", "expired-lease", "expired-deadline", "expired-authorizer", "revoked-authorizer", "revoked-worker", "changed-map", "changed-guards", "changed-broker", "cancelled-context"} {
		t.Run(kind, func(t *testing.T) {
			q, l, v, r, _ := mutationFixture(t)
			ctx := context.Background()
			switch kind {
			case "wrong-role":
				v.Role = scanevidence.CleanupObserverRole
			case "wrong-authorizer":
				v.ID = "different-authorizer"
			case "wrong-owner":
				v.Owner = "owner-b"
			case "wrong-engine":
				v.Engine = domain.Hash([]byte("other"))
			case "wrong-registry":
				v.Registry = domain.Hash([]byte("other"))
			case "wrong-policy":
				v.Policy = domain.Hash([]byte("other"))
			case "wrong-generation":
				r.Generation = strings.Repeat("f", 64)
			case "wrong-launch":
				r.Launch = domain.Hash([]byte("other"))
			case "wrong-tool":
				r.Tool = "syft"
			case "unknown-operation":
				r.Operation = "restart"
			case "cancel":
				if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
					t.Fatal(e)
				}
			case "terminal":
				q.S.DB.Exec("UPDATE scanner_jobs SET state='tool_error' WHERE id=?", l.Job.ID)
			case "held":
				q.S.DB.Exec("UPDATE scanner_dispatch SET state='cleanup_required'")
			case "expired-lease":
				q.S.DB.Exec("UPDATE scanner_dispatch SET lease_until=?", q.now().Unix())
			case "expired-deadline":
				now := q.now().Add(time.Hour)
				q.Now = func() time.Time { return now }
			case "expired-authorizer":
				now := q.now().Add(61 * time.Minute)
				q.Now = func() time.Time { return now }
			case "revoked-authorizer":
				q.S.DB.Exec("UPDATE scanner_authorizers SET state='revoked'")
			case "revoked-worker":
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=?", l.Worker)
			case "changed-map":
				q.S.DB.Exec("UPDATE repositories SET map_digest=? WHERE id=?", domain.Hash([]byte("changed")), l.Job.Input.Repository)
			case "changed-guards":
				q.Guards, _ = scanevidence.NewGuardSet(domain.Hash([]byte("new")), domain.Hash([]byte("newarm")))
			case "changed-broker":
				q.S.DB.Exec("UPDATE settings SET value='{}' WHERE key=?", brokerBindingKey)
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, e := q.AdmitMutation(ctx, v, r); e == nil {
				t.Fatal("invalid admission accepted")
			}
			var n int
			if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 0 {
				t.Fatal("denial created obligation", e)
			}
		})
	}
}
func TestGenerationClosureDoesNotSettleUnknownNativeResponse(t *testing.T) {
	for _, close := range []string{"cancel", "fail", "reconcile", "revoke"} {
		t.Run(close, func(t *testing.T) {
			q, l, v, r, _ := mutationFixture(t)
			m := mustAdmit(t, q, v, r)
			switch close {
			case "cancel":
				if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
					t.Fatal(e)
				}
			case "fail":
				if e := q.Fail(l, "SCANNER_EXECUTION_FAILED"); e != nil {
					t.Fatal(e)
				}
			case "reconcile":
				now := q.now().Add(20 * time.Second)
				q.Now = func() time.Time { return now }
				if e := q.Reconcile(); e != nil {
					t.Fatal(e)
				}
			case "revoke":
				a := &scannerauth.Registry{S: q.S, Now: q.Now}
				if e := a.RevokeAuthorizer(v.Owner, v.ID); e != nil {
					t.Fatal(e)
				}
			}
			var g, state string
			if e := q.S.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE job=?", l.Job.ID).Scan(&g); e != nil || g != "closed" {
				t.Fatal("closure lost", e)
			}
			if e := q.S.DB.QueryRow("SELECT state FROM scanner_mutation_intents WHERE id=?", m.ID).Scan(&state); e != nil || state != "pending" {
				t.Fatal("uncertain response was settled", e)
			}
			if _, e := q.AdmitMutation(context.Background(), v, r); e == nil {
				t.Fatal("closed generation admitted replay")
			}
			if _, e := q.S.DB.Exec("DELETE FROM scanner_mutation_intents WHERE id=?", m.ID); e == nil {
				t.Fatal("pending obligation deleted")
			}
			if close != "revoke" {
				mustComplete(t, q, v, m)
			}
		})
	}
}
func TestGenerationAdmissionCancellationRaceHasOneDurableOrdering(t *testing.T) {
	for i := 0; i < 8; i++ {
		q, l, v, r, _ := mutationFixture(t)
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		var admitted MutationAdmission
		var admitErr, cancelErr error
		go func() { defer wg.Done(); <-start; admitted, admitErr = q.AdmitMutation(context.Background(), v, r) }()
		go func() { defer wg.Done(); <-start; cancelErr = q.Cancel(l.Job.Owner, l.Job.ID) }()
		close(start)
		wg.Wait()
		if cancelErr != nil {
			t.Fatal(cancelErr)
		}
		var n int
		if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil {
			t.Fatal(e)
		}
		if (admitErr == nil && (n != 1 || admitted.Intent.State != "pending")) || (admitErr != nil && n != 0) {
			t.Fatal("transaction ordering lost obligation")
		}
		var state string
		q.S.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE job=?", l.Job.ID).Scan(&state)
		if state != "closed" {
			t.Fatal("race reopened generation")
		}
	}
}
func TestMutationHistoryAndScopeAreImmutable(t *testing.T) {
	q, l, v, r, b := mutationFixture(t)
	m := mustAdmit(t, q, v, r)
	for _, stmt := range []string{
		"UPDATE scanner_mutation_bindings SET namespace_digest='changed'",
		"DELETE FROM scanner_mutation_bindings",
		"UPDATE scanner_allocation_generations SET deadline=deadline+1",
		"UPDATE scanner_mutation_intents SET descriptor_digest='changed'",
		"DELETE FROM scanner_allocation_generations",
		"UPDATE scanner_mutation_intents SET state='completed'",
	} {
		if _, e := q.S.DB.Exec(stmt); e == nil {
			t.Fatal("history mutation accepted")
		}
	}
	if _, e := q.BindMutationAuthorizer(v.Owner, v.ID, b.Namespace); e != nil {
		t.Fatal("exact local binding replay refused", e)
	}
	if _, e := q.BindMutationAuthorizer(v.Owner, v.ID, domain.Hash([]byte("replacement namespace"))); e == nil {
		t.Fatal("namespace changed")
	}
	if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := q.S.DB.Exec("UPDATE scanner_allocation_generations SET state='open'"); e == nil {
		t.Fatal("generation reopened")
	}
	var state string
	if e := q.S.DB.QueryRow("SELECT state FROM scanner_mutation_intents WHERE id=?", m.ID).Scan(&state); e != nil || state != "pending" {
		t.Fatal(e)
	}
}
func TestGenerationCannotUseLegacyObserverLiveLaunch(t *testing.T) {
	q, l, v, r, _ := mutationFixture(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(dir, 0700)
	auth := &scannerauth.Registry{S: q.S, Now: q.Now}
	observer, e := auth.EnrollVerifierFile(v.Owner, "observer-a", 60, v.Engine, v.Registry, filepath.Join(dir, "observer"))
	if e != nil {
		t.Fatal(e)
	}
	var name string
	q.S.DB.QueryRow("SELECT container FROM scanner_launches WHERE job=?", r.Job).Scan(&name)
	if _, e = q.LiveLaunch(context.Background(), observer, name, strings.Repeat("b", 32)); e == nil {
		t.Fatal("observation-only gate bypassed durable admission")
	}
	if _, e = q.CleanupContext(context.Background(), observer, l.Job.ID); e != nil {
		t.Fatal("read-only cleanup metadata lost", e)
	}
}
func TestLegacyClaimGetsNoGenerationAndCannotBeAdopted(t *testing.T) {
	q, in, _ := fixture(t)
	l := enqueueClaim(t, q, in)
	var n int
	if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_allocation_generations WHERE job=?", l.Job.ID).Scan(&n); e != nil || n != 0 {
		t.Fatal(e)
	}
	if _, e := q.GenerationForAuthorizer(context.Background(), scanevidence.AuthorizerIdentity{}, l.Job.ID); e == nil || e == sql.ErrNoRows {
		t.Fatal("legacy granted generation")
	}
}

func TestMutationAuditFailureRollsBackAdmissionAndCompletion(t *testing.T) {
	q, _, v, r, _ := mutationFixture(t)
	reject := func() {
		t.Helper()
		if _, e := q.S.DB.Exec("CREATE TRIGGER reject_mutation_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); e != nil {
			t.Fatal(e)
		}
	}
	reject()
	if _, e := q.AdmitMutation(context.Background(), v, r); e == nil {
		t.Fatal("unaudited admission committed")
	}
	var n int
	if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 0 {
		t.Fatal("admission survived audit failure", e)
	}
	if _, e := q.S.DB.Exec("DROP TRIGGER reject_mutation_audit"); e != nil {
		t.Fatal(e)
	}
	m := mustAdmit(t, q, v, r)
	reject()
	c := MutationCompletion{Intent: m.ID, Generation: r.Generation, Status: 201, EngineID: strings.Repeat("c", 64), Response: domain.Hash([]byte("response"))}
	if _, e := q.CompleteMutation(context.Background(), v, c); e == nil {
		t.Fatal("unaudited completion committed")
	}
	var state string
	if e := q.S.DB.QueryRow("SELECT state FROM scanner_mutation_intents WHERE id=?", m.ID).Scan(&state); e != nil || state != "pending" {
		t.Fatal("uncertain obligation lost", e)
	}
}

func TestMutationCompletionRejectsWrongScopeAndNativeIdentity(t *testing.T) {
	q, _, v, r, _ := mutationFixture(t)
	m := mustAdmit(t, q, v, r)
	baseline := MutationCompletion{Intent: m.ID, Generation: r.Generation, Status: 201, EngineID: strings.Repeat("c", 64), Response: domain.Hash([]byte("response"))}
	for _, kind := range []string{"owner", "role", "authorizer", "generation", "intent", "status", "engine-id", "response"} {
		c := baseline
		caller := v
		switch kind {
		case "owner":
			caller.Owner = "owner-b"
		case "role":
			caller.Role = scanevidence.CleanupObserverRole
		case "authorizer":
			caller.ID = "different-authorizer"
		case "generation":
			c.Generation = strings.Repeat("f", 64)
		case "intent":
			c.Intent = domain.Hash([]byte("unknown"))
		case "status":
			c.Status = 500
		case "engine-id":
			c.EngineID = "aegis-scan-" + strings.Repeat("c", 32)
		case "response":
			c.Response = ""
		}
		if _, e := q.CompleteMutation(context.Background(), caller, c); e == nil {
			t.Fatal("invalid completion accepted", kind)
		}
	}
	var state string
	if e := q.S.DB.QueryRow("SELECT state FROM scanner_mutation_intents WHERE id=?", m.ID).Scan(&state); e != nil || state != "pending" {
		t.Fatal("failed completion settled intent", e)
	}
}

func TestSelectedBindingRevocationClosesGenerationAndKeepsHold(t *testing.T) {
	q, l, v, _, _ := mutationFixture(t)
	// This synthetic fixture starts with an existing generation. Prove closure
	// and history stay intact even when another queued claim cannot run.
	if _, e := q.S.DB.Exec("UPDATE scanner_mutation_bindings SET state='revoked' WHERE owner=?", v.Owner); e != nil {
		t.Fatal(e)
	}
	if e := q.Guard(l); e == nil {
		t.Fatal("revoked selected binding kept worker live")
	}
	var state string
	if e := q.S.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE job=?", l.Job.ID).Scan(&state); e != nil || state != "closed" {
		t.Fatal("selected binding revocation did not close generation", e)
	}
	if _, e := q.Claim(l.Worker, l.Job.Owner); e != ErrCleanup {
		t.Fatal("retained hold ignored", e)
	}
}

func TestMutationObligationSurvivesControllerRestart(t *testing.T) {
	q, _, v, r, _ := mutationFixture(t)
	m := mustAdmit(t, q, v, r)
	if e := q.S.DB.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(q.S.Path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	q.S = reopened
	replay, e := q.AdmitMutation(context.Background(), v, r)
	if e != nil || !replay.Replay || replay.Intent != m {
		t.Fatal("restart lost admitted obligation", e)
	}
	mustComplete(t, q, v, m)
	if _, e = q.S.DB.Exec("DELETE FROM scanner_dispatch"); e == nil {
		t.Fatal("restart or completion freed unverified slot")
	}
}

func TestSelectedGenerationClaimAuditFailureRollsBackAllAdmission(t *testing.T) {
	q, in, _ := fixture(t)
	provisionJournalFixture(t, q)
	if _, e := q.BindBroker("owner-a", "trusted-worker"); e != nil {
		t.Fatal(e)
	}
	auth := &scannerauth.Registry{S: q.S, Now: q.Now}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(dir, 0700)
	v, e := auth.EnrollAuthorizerFile("owner-a", "authorizer-a", 60, domain.Hash([]byte("engine")), domain.Hash([]byte("registry")), domain.Hash([]byte("policy")), filepath.Join(dir, "credential"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.BindMutationAuthorizer(v.Owner, v.ID, domain.Hash([]byte("namespace"))); e != nil {
		t.Fatal(e)
	}
	j, e := q.Enqueue(v.Owner, "generation-claim-audit", in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.S.DB.Exec("CREATE TRIGGER reject_generation_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e = q.Claim("trusted-worker", v.Owner); e == nil {
		t.Fatal("unaudited claim committed")
	}
	for _, table := range []string{"scanner_dispatch", "scanner_allocation_generations"} {
		var n int
		if e = q.S.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("failed claim retained partial state", table, e)
		}
	}
	current, e := q.Get(v.Owner, j.ID)
	if e != nil || current.State != "queued" {
		t.Fatal("failed claim changed job", e)
	}
}

func TestMutationBindingRefusesAdoptingLegacyDispatch(t *testing.T) {
	q, in, _ := fixture(t)
	provisionJournalFixture(t, q)
	if _, e := q.BindBroker("owner-a", "trusted-worker"); e != nil {
		t.Fatal(e)
	}
	auth := &scannerauth.Registry{S: q.S, Now: q.Now}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(dir, 0700)
	v, e := auth.EnrollAuthorizerFile("owner-a", "authorizer-a", 60, domain.Hash([]byte("engine")), domain.Hash([]byte("registry")), domain.Hash([]byte("policy")), filepath.Join(dir, "credential"))
	if e != nil {
		t.Fatal(e)
	}
	enqueueClaim(t, q, in)
	if _, e = q.BindMutationAuthorizer(v.Owner, v.ID, domain.Hash([]byte("namespace"))); e != ErrCleanup {
		t.Fatal("adopted existing dispatch", e)
	}
	var n int
	if e = q.S.DB.QueryRow("SELECT count(*) FROM scanner_mutation_bindings").Scan(&n); e != nil || n != 0 {
		t.Fatal("legacy dispatch acquired selected binding", e)
	}
}
