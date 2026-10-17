// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"strings"
	"testing"
	"time"
)

func TestCompletedMutationAcknowledgementDoesNotTouchSuccessor(t *testing.T) {
	q, l, v, r, b := mutationFixture(t)
	reconciler := enrollReconciliationFixture(t, q, b)
	m := mustAdmit(t, q, v, r)
	c := mustComplete(t, q, v, m)
	start := r
	start.Operation = "start"
	start.EngineID = c.EngineID
	start.Descriptor = domain.Hash([]byte("start descriptor"))
	mustComplete(t, q, v, mustAdmit(t, q, v, start))
	remove := start
	remove.Operation = "remove"
	remove.Descriptor = domain.Hash([]byte("remove descriptor"))
	mustComplete(t, q, v, mustAdmit(t, q, v, remove))
	if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	// Release through the evidence-bound transaction (ADR 057); the database
	// refuses any other release.
	now := q.now()
	q.Now = func() time.Time { return now.Add(20 * time.Second) }
	if e := q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	s, e := q.ReconciliationSnapshot(context.Background(), reconciler, reconciliationRequest(l, r))
	if e != nil {
		t.Fatal(e)
	}
	absent, e := scanevidence.RequiredAbsences(s.Membership)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.ConfirmCleanup(context.Background(), reconciler, scanevidence.CleanupConfirmationRequest{Job: l.Job.ID, Generation: r.Generation, Membership: s.MembershipHash, Engine: s.Membership.Binding.Document.Engine, Namespace: s.Membership.Binding.Document.Namespace, Absent: absent}); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Enqueue(l.Job.Owner, "successor-after-release", l.Job.Input); e != nil {
		t.Fatal(e)
	}
	next, e := q.Claim(l.Worker, l.Job.Owner)
	if e != nil || next.Job.ID == l.Job.ID {
		t.Fatal("successor fixture did not claim", e)
	}
	var before, after string
	read := func(out *string) {
		t.Helper()
		if e := q.S.DB.QueryRow(`SELECT d.job||d.worker||d.token_hash||d.lease_until||d.deadline||d.state||d.guard_set_digest||g.id||g.state FROM scanner_dispatch d JOIN scanner_allocation_generations g ON g.job=d.job`).Scan(out); e != nil {
			t.Fatal(e)
		}
	}
	read(&before)
	var auditsBefore, auditsAfter int
	if e = q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&auditsBefore); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 3; n++ {
		got, err := q.CompleteMutation(context.Background(), v, c)
		if err != nil || got.State != "completed" || got.ID != m.ID || got.Response != c.Response {
			t.Fatal("original completed acknowledgement unavailable", err)
		}
	}
	bad := c
	bad.Response = domain.Hash([]byte("changed callback"))
	if _, e = q.CompleteMutation(context.Background(), v, bad); e == nil {
		t.Fatal("changed historical response accepted")
	}
	if _, e = q.AdmitMutation(context.Background(), v, r); e == nil {
		t.Fatal("historical acknowledgement reopened admission")
	}
	read(&after)
	if e = q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&auditsAfter); e != nil || before != after || auditsBefore != auditsAfter {
		t.Fatal("read-only acknowledgement changed successor or audit", e)
	}
}

func TestCompletedMutationAcknowledgementChecksOriginalIdentity(t *testing.T) {
	for _, kind := range []string{"owner", "role", "authorizer", "engine", "registry", "policy", "generation", "status", "native-id", "revoked", "expired", "cancelled-context"} {
		t.Run(kind, func(t *testing.T) {
			q, _, v, r, _ := mutationFixture(t)
			c := mustComplete(t, q, v, mustAdmit(t, q, v, r))
			ctx := context.Background()
			switch kind {
			case "owner":
				v.Owner = "owner-b"
			case "role":
				v.Role = scanevidence.CleanupObserverRole
			case "authorizer":
				v.ID = "different-authorizer"
			case "engine":
				v.Engine = domain.Hash([]byte("other"))
			case "registry":
				v.Registry = domain.Hash([]byte("other"))
			case "policy":
				v.Policy = domain.Hash([]byte("other"))
			case "generation":
				c.Generation = strings.Repeat("e", 64)
			case "status":
				c.Status = 204
			case "native-id":
				c.EngineID = strings.Repeat("d", 64)
			case "revoked":
				if e := (&scannerauth.Registry{S: q.S, Now: q.Now}).RevokeAuthorizer(v.Owner, v.ID); e != nil {
					t.Fatal(e)
				}
			case "expired":
				now := q.now().Add(61 * time.Minute)
				q.Now = func() time.Time { return now }
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, e := q.CompleteMutation(ctx, v, c); e == nil {
				t.Fatal("invalid historical acknowledgement accepted")
			}
		})
	}
}

func TestHistoricalAcknowledgementCannotSettlePendingAfterBindingWithdrawal(t *testing.T) {
	q, _, v, r, b := mutationFixture(t)
	c := mustComplete(t, q, v, mustAdmit(t, q, v, r))
	r.Operation = "start"
	r.EngineID = c.EngineID
	r.Descriptor = domain.Hash([]byte("start descriptor"))
	pending := mustAdmit(t, q, v, r)
	if _, e := q.S.DB.Exec("UPDATE scanner_mutation_bindings SET state='revoked' WHERE digest=?", b.Digest); e != nil {
		t.Fatal(e)
	}
	// Current configuration no longer confers mutation authority. The original
	// enrollment still authenticates a read of its already completed response.
	q.Guards = scanevidence.GuardSet{}
	if _, e := q.CompleteMutation(context.Background(), v, c); e != nil {
		t.Fatal("retained original acknowledgement depended on live binding", e)
	}
	newCompletion := MutationCompletion{Intent: pending.ID, Generation: r.Generation, Status: 204, EngineID: r.EngineID, Response: domain.Hash([]byte("response"))}
	if _, e := q.CompleteMutation(context.Background(), v, newCompletion); e == nil {
		t.Fatal("read-only acknowledgement path settled pending obligation")
	}
	var state string
	if e := q.S.DB.QueryRow("SELECT state FROM scanner_mutation_intents WHERE id=?", pending.ID).Scan(&state); e != nil || state != "pending" {
		t.Fatal("pending obligation was changed", e)
	}
}
