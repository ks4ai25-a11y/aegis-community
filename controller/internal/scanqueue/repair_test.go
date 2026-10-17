// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"context"
	"strings"
	"testing"
	"time"
)

// crashedFixture leaves a closed generation whose obligations stop at the
// requested point, as if the authorizer died mid-write: "create" leaves the
// create pending, "start" the start, "remove" the removal.
func crashedFixture(t *testing.T, pendingAt string) (*Queue, Lease, scanevidence.AuthorizerIdentity, scanevidence.ReconcilerIdentity, MutationRequest, MutationBinding) {
	t.Helper()
	q, l, authorizer, r, b := mutationFixture(t)
	v := enrollReconciliationFixture(t, q, b)
	created := mustAdmit(t, q, authorizer, r)
	if pendingAt != "create" {
		mustComplete(t, q, authorizer, created)
		start := r
		start.Operation, start.EngineID, start.Descriptor = "start", strings.Repeat("c", 64), domain.Hash([]byte("start"))
		started := mustAdmit(t, q, authorizer, start)
		if pendingAt != "start" {
			mustComplete(t, q, authorizer, started)
		}
	}
	if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	if pendingAt == "remove" {
		remove := r
		remove.Operation, remove.EngineID, remove.Descriptor = "remove", strings.Repeat("c", 64), domain.Hash([]byte("remove"))
		mustAdmit(t, q, authorizer, remove)
	}
	now := q.now()
	q.Now = func() time.Time { return now.Add(20 * time.Second) }
	if e := q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	return q, l, authorizer, v, r, b
}

func snapshotFor(t *testing.T, q *Queue, v scanevidence.ReconcilerIdentity, l Lease, r MutationRequest) scanevidence.ReconciliationSnapshot {
	t.Helper()
	s, e := q.ReconciliationSnapshot(context.Background(), v, reconciliationRequest(l, r))
	if e != nil {
		t.Fatal("snapshot unavailable", e)
	}
	return s
}

func repairRequest(s scanevidence.ReconciliationSnapshot, b MutationBinding, outcome, engineID string) scanevidence.MutationRepairRequest {
	m := s.Membership
	req := scanevidence.MutationRepairRequest{Job: m.Job, Generation: m.Generation.ID, Membership: s.MembershipHash, Engine: b.Engine, Namespace: b.Namespace, Fence: scanevidence.RepairFence{Policy: scanevidence.AdmittedJournalSeal(b.Policy, b.Digest), Quarantine: domain.Hash([]byte("quarantine")), Activation: domain.Hash([]byte("activation"))}}
	for _, p := range scanevidence.PendingIntents(m) {
		id := engineID
		if p.Request.Operation != "create" {
			id = p.Request.EngineID
		}
		req.Resolutions = append(req.Resolutions, scanevidence.MutationResolution{Intent: p.ID, Operation: p.Request.Operation, Outcome: outcome, EngineID: id, Evidence: domain.Hash([]byte("evidence " + p.ID))})
	}
	return req
}

func intentState(t *testing.T, q *Queue, generation, operation string) (string, int, string) {
	t.Helper()
	var state, engine string
	var status int
	if e := q.S.DB.QueryRow("SELECT state,response_status,result_engine_id FROM scanner_mutation_intents WHERE generation=? AND operation=?", generation, operation).Scan(&state, &status, &engine); e != nil {
		t.Fatal(e)
	}
	return state, status, engine
}

func confirmFor(t *testing.T, q *Queue, v scanevidence.ReconcilerIdentity, l Lease, r MutationRequest) (scanevidence.CleanupConfirmation, error) {
	t.Helper()
	s := snapshotFor(t, q, v, l, r)
	absent, e := scanevidence.RequiredAbsences(s.Membership)
	if e != nil {
		return scanevidence.CleanupConfirmation{}, e
	}
	b := s.Membership.Binding.Document
	return q.ConfirmCleanup(context.Background(), v, scanevidence.CleanupConfirmationRequest{Job: l.Job.ID, Generation: r.Generation, Membership: s.MembershipHash, Engine: b.Engine, Namespace: b.Namespace, Absent: absent})
}

func TestRepairCreatedRecordsObservedIDThenNormalRemoveAndRelease(t *testing.T) {
	q, l, authorizer, v, r, b := crashedFixture(t, "create")
	if _, e := confirmFor(t, q, v, l, r); e == nil {
		t.Fatal("pending create released")
	}
	observed := strings.Repeat("e", 64)
	out, e := q.RepairMutations(context.Background(), v, repairRequest(snapshotFor(t, q, v, l, r), b, scanevidence.RepairCreated, observed))
	if e != nil || len(out.Repairs) != 1 || out.CleanupReleased || !out.Repairs[0].Valid() || out.Repairs[0].Resolution.EngineID != observed {
		t.Fatal("present create not repaired", e)
	}
	// Explicit repaired status, never a fabricated native 201.
	if state, status, engine := intentState(t, q, r.Generation, "create"); state != "repaired" || status != 0 || engine != observed {
		t.Fatal("repair recorded a native-looking status", state, status, engine)
	}
	var audits int
	if e = q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE json_extract(document,'$.action')='scanner.mutation_repaired' AND json_extract(document,'$.object_id')=?", out.Repairs[0].Resolution.Intent).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("repair not audited", audits, e)
	}
	if !dispatchHeld(t, q, l.Job.ID) {
		t.Fatal("repair released the slot")
	}
	// A repaired create still needs a removal: release refuses until then.
	if _, e = confirmFor(t, q, v, l, r); e == nil {
		t.Fatal("repaired create released without removal")
	}
	// No new start after repair; removal follows the normal admitted path.
	start := r
	start.Operation, start.EngineID, start.Descriptor = "start", observed, domain.Hash([]byte("late start"))
	if _, e = q.AdmitMutation(context.Background(), authorizer, start); e == nil {
		t.Fatal("start admitted after crash repair")
	}
	remove := r
	remove.Operation, remove.EngineID, remove.Descriptor = "remove", observed, domain.Hash([]byte("remove"))
	removed := mustAdmit(t, q, authorizer, remove)
	if _, e = q.CompleteMutation(context.Background(), authorizer, MutationCompletion{Intent: removed.ID, Generation: r.Generation, Status: 204, EngineID: observed, Response: domain.Hash([]byte("native remove"))}); e != nil {
		t.Fatal(e)
	}
	c, e := confirmFor(t, q, v, l, r)
	if e != nil || !c.Released || len(c.Request.Absent) != 1 || c.Request.Absent[0].EngineID != observed {
		t.Fatal("repaired and removed allocation not releasable", e)
	}
	if dispatchHeld(t, q, l.Job.ID) {
		t.Fatal("slot still held after release")
	}
}

func TestRepairNotCreatedLeavesOnlyExactNameAbsenceForRelease(t *testing.T) {
	q, l, authorizer, v, r, b := crashedFixture(t, "create")
	if _, e := q.RepairMutations(context.Background(), v, repairRequest(snapshotFor(t, q, v, l, r), b, scanevidence.RepairNotCreated, "")); e != nil {
		t.Fatal(e)
	}
	if state, status, engine := intentState(t, q, r.Generation, "create"); state != "repaired" || status != 0 || engine != "" {
		t.Fatal("not-created repair state", state, status, engine)
	}
	// Nothing was created, so nothing may be started or removed.
	remove := r
	remove.Operation, remove.EngineID, remove.Descriptor = "remove", strings.Repeat("e", 64), domain.Hash([]byte("remove"))
	if _, e := q.AdmitMutation(context.Background(), authorizer, remove); e == nil {
		t.Fatal("removal admitted for a create repaired as not created")
	}
	c, e := confirmFor(t, q, v, l, r)
	if e != nil || len(c.Request.Absent) != 1 || c.Request.Absent[0].EngineID != "" {
		t.Fatal("name-only release refused", e)
	}
}

func TestRepairPendingStartAndRemove(t *testing.T) {
	for _, tc := range []struct{ at, outcome string }{{"start", scanevidence.RepairStarted}, {"start", scanevidence.RepairNotStarted}, {"remove", scanevidence.RepairRemoved}} {
		t.Run(tc.at+"/"+tc.outcome, func(t *testing.T) {
			q, l, authorizer, v, r, b := crashedFixture(t, tc.at)
			if _, e := q.RepairMutations(context.Background(), v, repairRequest(snapshotFor(t, q, v, l, r), b, tc.outcome, "")); e != nil {
				t.Fatal(e)
			}
			if state, status, engine := intentState(t, q, r.Generation, tc.at); state != "repaired" || status != 0 || engine != strings.Repeat("c", 64) {
				t.Fatal("repair state", state, status, engine)
			}
			if tc.at == "start" {
				remove := r
				remove.Operation, remove.EngineID, remove.Descriptor = "remove", strings.Repeat("c", 64), domain.Hash([]byte("remove"))
				mustComplete(t, q, authorizer, mustAdmit(t, q, authorizer, remove))
			}
			if c, e := confirmFor(t, q, v, l, r); e != nil || !c.Released {
				t.Fatal("repaired lifecycle not releasable", e)
			}
		})
	}
}

func TestRepairRefusesUnfencedChangedOrIncompleteEvidence(t *testing.T) {
	q, l, authorizer, v, r, b := crashedFixture(t, "create")
	good := repairRequest(snapshotFor(t, q, v, l, r), b, scanevidence.RepairCreated, strings.Repeat("e", 64))
	mutate := func(f func(*scanevidence.MutationRepairRequest)) scanevidence.MutationRepairRequest {
		x := good
		x.Resolutions = append([]scanevidence.MutationResolution(nil), good.Resolutions...)
		f(&x)
		return x
	}
	cases := map[string]scanevidence.MutationRepairRequest{
		"stale membership":     mutate(func(x *scanevidence.MutationRepairRequest) { x.Membership = domain.Hash([]byte("old")) }),
		"other journal seal":   mutate(func(x *scanevidence.MutationRepairRequest) { x.Fence.Policy = domain.Hash([]byte("other policy")) }),
		"other engine":         mutate(func(x *scanevidence.MutationRepairRequest) { x.Engine = domain.Hash([]byte("other engine")) }),
		"other namespace":      mutate(func(x *scanevidence.MutationRepairRequest) { x.Namespace = domain.Hash([]byte("other namespace")) }),
		"wrong operation":      mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions[0].Operation = "start" }),
		"outcome for start":    mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions[0].Outcome = scanevidence.RepairStarted }),
		"created without id":   mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions[0].EngineID = "" }),
		"not created with id":  mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions[0].Outcome = scanevidence.RepairNotCreated }),
		"unknown intent":       mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions[0].Intent = domain.Hash([]byte("other")) }),
		"missing fence":        mutate(func(x *scanevidence.MutationRepairRequest) { x.Fence.Activation = "" }),
		"no resolutions":       mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions = nil }),
		"other generation":     mutate(func(x *scanevidence.MutationRepairRequest) { x.Generation = strings.Repeat("9", 64) }),
		"duplicate resolution": mutate(func(x *scanevidence.MutationRepairRequest) { x.Resolutions = append(x.Resolutions, x.Resolutions[0]) }),
	}
	for name, req := range cases {
		if _, e := q.RepairMutations(context.Background(), v, req); e == nil {
			t.Fatal(name, "accepted")
		}
	}
	if state, _, _ := intentState(t, q, r.Generation, "create"); state != "pending" {
		t.Fatal("refused repair changed the intent", state)
	}
	// A late native completion wins over a later repair: exactly one ordering.
	created, _, _, e := q.MutationForAuthorizer(context.Background(), authorizer, r.Generation, good.Resolutions[0].Intent)
	if e != nil {
		t.Fatal(e)
	}
	mustComplete(t, q, authorizer, created)
	if _, e = q.RepairMutations(context.Background(), v, good); e == nil {
		t.Fatal("repair overwrote a native completion")
	}
}

func TestRepairRefusesOpenGenerationAndRevokedBinding(t *testing.T) {
	q, l, authorizer, r, b := mutationFixture(t)
	v := enrollReconciliationFixture(t, q, b)
	mustAdmit(t, q, authorizer, r)
	req := scanevidence.MutationRepairRequest{Job: l.Job.ID, Generation: r.Generation, Membership: domain.Hash([]byte("m")), Engine: b.Engine, Namespace: b.Namespace, Fence: scanevidence.RepairFence{Policy: scanevidence.AdmittedJournalSeal(b.Policy, b.Digest), Quarantine: domain.Hash([]byte("q")), Activation: domain.Hash([]byte("a"))}, Resolutions: []scanevidence.MutationResolution{{Intent: domain.Hash([]byte("i")), Operation: "create", Outcome: scanevidence.RepairNotCreated, Evidence: domain.Hash([]byte("e"))}}}
	if _, e := q.RepairMutations(context.Background(), v, req); e != ErrContextUnbound {
		t.Fatal("open generation repaired", e)
	}

	q, l, _, v, r, b = crashedFixture(t, "create")
	good := repairRequest(snapshotFor(t, q, v, l, r), b, scanevidence.RepairNotCreated, "")
	if _, e := q.S.DB.Exec("UPDATE scanner_mutation_bindings SET state='revoked' WHERE digest=?", b.Digest); e != nil {
		t.Fatal(e)
	}
	if _, e := q.RepairMutations(context.Background(), v, good); e != ErrContextUnbound {
		t.Fatal("revoked binding repaired", e)
	}
}

func TestRepairTriggersAllowOnlyMatchingRecords(t *testing.T) {
	q, l, _, v, r, b := crashedFixture(t, "create")
	db := q.S.DB
	if _, e := db.Exec("UPDATE scanner_mutation_intents SET state='repaired',response_digest=?,response_status=0,result_engine_id='',completed_at='2026-10-17T00:00:00Z' WHERE generation=?", domain.Hash([]byte("forged")), r.Generation); e == nil {
		t.Fatal("pending intent repaired without a record")
	}
	if _, e := db.Exec("UPDATE scanner_mutation_intents SET state='completed',response_digest=?,response_status=200,result_engine_id=?,completed_at='x' WHERE generation=?", domain.Hash([]byte("fake")), strings.Repeat("e", 64), r.Generation); e == nil {
		t.Fatal("fake native status accepted")
	}
	out, e := q.RepairMutations(context.Background(), v, repairRequest(snapshotFor(t, q, v, l, r), b, scanevidence.RepairNotCreated, ""))
	if e != nil {
		t.Fatal(e)
	}
	for _, statement := range []string{
		"UPDATE scanner_mutation_repairs SET outcome='created'",
		"DELETE FROM scanner_mutation_repairs",
		"UPDATE scanner_mutation_intents SET state='pending',response_digest='',completed_at=''",
		"UPDATE scanner_mutation_intents SET state='completed',response_status=201,result_engine_id='" + strings.Repeat("e", 64) + "'",
		"DELETE FROM scanner_mutation_intents",
	} {
		if _, e = db.Exec(statement); e == nil {
			t.Fatal("repair history changed:", statement)
		}
	}
	// A second record for an intent that is no longer pending is refused.
	if _, e = db.Exec("INSERT INTO scanner_mutation_repairs(intent,generation,job,reconciler,outcome,engine_id,digest,document,created_at) SELECT intent,generation,job,reconciler,outcome,engine_id,?,document,created_at FROM scanner_mutation_repairs", domain.Hash([]byte("second"))); e == nil {
		t.Fatal("second repair record accepted")
	}
	if out.Repairs[0].Digest == "" {
		t.Fatal("repair digest missing")
	}
}

func TestMutationForAuthorizerReadsRepairAndNeverAdmittedIntent(t *testing.T) {
	q, l, authorizer, v, r, b := crashedFixture(t, "create")
	out, e := q.RepairMutations(context.Background(), v, repairRequest(snapshotFor(t, q, v, l, r), b, scanevidence.RepairCreated, strings.Repeat("e", 64)))
	if e != nil {
		t.Fatal(e)
	}
	id := out.Repairs[0].Resolution.Intent
	m, rec, found, e := q.MutationForAuthorizer(context.Background(), authorizer, r.Generation, id)
	read := scanevidence.NewAuthorizerIntentRead(found, m, rec)
	if e != nil || !found || rec == nil || !read.Valid(scanevidence.AuthorizerIntentRequest{Generation: r.Generation, Intent: id}) || m.State != "repaired" {
		t.Fatal("repaired intent unreadable", e)
	}
	_, rec, found, e = q.MutationForAuthorizer(context.Background(), authorizer, r.Generation, domain.Hash([]byte("never admitted")))
	if e != nil || found || rec != nil {
		t.Fatal("never-admitted intent reported", found, e)
	}

	q, _, authorizer, r, _ = mutationFixture(t)
	if _, _, _, e = q.MutationForAuthorizer(context.Background(), authorizer, r.Generation, domain.Hash([]byte("not yet"))); e == nil {
		t.Fatal("absence reported while admission is open")
	}
}

func TestWorkerReadsRetainedConfirmationOnlyAfterReleaseOfItsOwnContainer(t *testing.T) {
	q, l, _, v, r, b := crashedFixture(t, "create")
	s := snapshotFor(t, q, v, l, r)
	name := s.Membership.Launches[0].Document.Plan.Container
	if _, e := q.CleanupConfirmationForWorker(context.Background(), l.Worker, l.Job.Owner, name); e == nil {
		t.Fatal("held allocation reported as confirmed")
	}
	if _, e := q.RepairMutations(context.Background(), v, repairRequest(s, b, scanevidence.RepairNotCreated, "")); e != nil {
		t.Fatal(e)
	}
	if _, e := confirmFor(t, q, v, l, r); e != nil {
		t.Fatal(e)
	}
	c, e := q.CleanupConfirmationForWorker(context.Background(), l.Worker, l.Job.Owner, name)
	if a, ok := c.Absence(name); e != nil || !ok || a.EngineID != "" {
		t.Fatal("released confirmation unreadable for its own container", e)
	}
	if _, e = q.CleanupConfirmationForWorker(context.Background(), "other-worker", l.Job.Owner, name); e == nil {
		t.Fatal("another worker read the confirmation")
	}
	if _, e = q.CleanupConfirmationForWorker(context.Background(), l.Worker, l.Job.Owner, "aegis-scan-"+strings.Repeat("0", 32)); e == nil {
		t.Fatal("unknown container reported as confirmed")
	}
}
