// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// releasableFixture drives one job through create, start and remove, cancels
// it and expires its lease, leaving the dispatch held as cleanup_required.
func releasableFixture(t *testing.T, removeCompleted bool) (*Queue, Lease, scanevidence.ReconcilerIdentity, scanevidence.CleanupConfirmationRequest) {
	t.Helper()
	q, l, authorizer, r, b := mutationFixture(t)
	v := enrollReconciliationFixture(t, q, b)
	mustComplete(t, q, authorizer, mustAdmit(t, q, authorizer, r))
	start := r
	start.Operation, start.EngineID, start.Descriptor = "start", strings.Repeat("c", 64), domain.Hash([]byte("start"))
	mustComplete(t, q, authorizer, mustAdmit(t, q, authorizer, start))
	if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	remove := start
	remove.Operation, remove.Descriptor = "remove", domain.Hash([]byte("remove"))
	removed := mustAdmit(t, q, authorizer, remove)
	if removeCompleted {
		mustComplete(t, q, authorizer, removed)
	}
	now := q.now()
	q.Now = func() time.Time { return now.Add(20 * time.Second) }
	if e := q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	s, e := q.ReconciliationSnapshot(context.Background(), v, reconciliationRequest(l, r))
	if e != nil {
		t.Fatal("snapshot unavailable", e)
	}
	absent, _ := scanevidence.RequiredAbsences(s.Membership)
	if absent == nil {
		absent = []scanevidence.CleanupAbsence{{Tool: "bandit", Container: s.Membership.Launches[0].Document.Plan.Container, EngineID: strings.Repeat("c", 64)}}
	}
	b2 := s.Membership.Binding.Document
	return q, l, v, scanevidence.CleanupConfirmationRequest{Job: l.Job.ID, Generation: r.Generation, Membership: s.MembershipHash, Engine: b2.Engine, Namespace: b2.Namespace, Absent: absent}
}

func dispatchHeld(t *testing.T, q *Queue, job string) bool {
	t.Helper()
	var n int
	if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch WHERE job=?", job).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n == 1
}

func TestConfirmCleanupReleasesDispatchOnceAndRetainsConfirmation(t *testing.T) {
	q, l, v, req := releasableFixture(t, true)
	if len(req.Absent) != 1 || req.Absent[0].EngineID != strings.Repeat("c", 64) {
		t.Fatal("required absences not derived from membership", req.Absent)
	}
	c, e := q.ConfirmCleanup(context.Background(), v, req)
	if e != nil || !c.Released || c.Reconciler != v.ID || !hashLike(c.Digest) {
		t.Fatal("confirmed cleanup refused", e)
	}
	if dispatchHeld(t, q, l.Job.ID) {
		t.Fatal("dispatch still held after release")
	}
	if st, e := q.Status(l.Job.Owner, l.Job.ID); e != nil || st.Admission != "cleanup_confirmed" {
		t.Fatal("released job status unreadable", st.Admission, e)
	}
	var state string
	if e = q.S.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE job=?", l.Job.ID).Scan(&state); e != nil || state != "released" {
		t.Fatal("generation not released", state, e)
	}
	replay, e := q.ConfirmCleanup(context.Background(), v, req)
	if e != nil || replay.Digest != c.Digest || replay.Confirmed != c.Confirmed || !sameRequest(replay.Request, c.Request) {
		t.Fatal("replay changed confirmation", e)
	}
	changed := req
	changed.Absent = []scanevidence.CleanupAbsence{{Tool: "bandit", Container: req.Absent[0].Container}}
	if _, e = q.ConfirmCleanup(context.Background(), v, changed); e != ErrConflict {
		t.Fatal("conflicting replay accepted", e)
	}
	if _, e = q.S.DB.Exec("UPDATE scanner_cleanup_confirmations SET reconciler='x'"); e == nil {
		t.Fatal("confirmation mutable")
	}
	if _, e = q.S.DB.Exec("DELETE FROM scanner_cleanup_confirmations"); e == nil {
		t.Fatal("confirmation deletable")
	}
	var audits int
	if e = q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE json_extract(document,'$.action')='scanner.cleanup_confirmed'").Scan(&audits); e != nil || audits != 1 {
		t.Fatal("release not audited exactly once", audits, e)
	}
}

func TestConfirmCleanupRefusesUnresolvedOrMismatchedObservation(t *testing.T) {
	cases := map[string]func(*scanevidence.CleanupConfirmationRequest){
		"membership":     func(r *scanevidence.CleanupConfirmationRequest) { r.Membership = domain.Hash([]byte("other")) },
		"engine":         func(r *scanevidence.CleanupConfirmationRequest) { r.Engine = domain.Hash([]byte("other engine")) },
		"namespace":      func(r *scanevidence.CleanupConfirmationRequest) { r.Namespace = domain.Hash([]byte("other namespace")) },
		"missing-id":     func(r *scanevidence.CleanupConfirmationRequest) { r.Absent[0].EngineID = "" },
		"other-id":       func(r *scanevidence.CleanupConfirmationRequest) { r.Absent[0].EngineID = strings.Repeat("d", 64) },
		"omitted":        func(r *scanevidence.CleanupConfirmationRequest) { r.Absent = []scanevidence.CleanupAbsence{} },
		"pending-remove": nil,
	}
	for kind, mutate := range cases {
		t.Run(kind, func(t *testing.T) {
			q, l, v, req := releasableFixture(t, mutate != nil)
			if mutate != nil {
				req.Absent = append([]scanevidence.CleanupAbsence(nil), req.Absent...)
				mutate(&req)
			}
			if _, e := q.ConfirmCleanup(context.Background(), v, req); e == nil {
				t.Fatal("unsafe release accepted")
			}
			if !dispatchHeld(t, q, l.Job.ID) {
				t.Fatal("refused release freed dispatch")
			}
			var n int
			if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_cleanup_confirmations").Scan(&n); e != nil || n != 0 {
				t.Fatal("refused release recorded a confirmation")
			}
		})
	}
}

func TestConfirmCleanupRefusesLiveJob(t *testing.T) {
	q, l, authorizer, r, b := mutationFixture(t)
	v := enrollReconciliationFixture(t, q, b)
	mustAdmit(t, q, authorizer, r)
	if e := q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	s, e := q.ReconciliationSnapshot(context.Background(), v, reconciliationRequest(l, r))
	if e != nil {
		t.Fatal(e)
	}
	req := scanevidence.CleanupConfirmationRequest{Job: l.Job.ID, Generation: r.Generation, Membership: s.MembershipHash, Engine: s.Membership.Binding.Document.Engine, Namespace: s.Membership.Binding.Document.Namespace, Absent: []scanevidence.CleanupAbsence{}}
	if _, e = q.ConfirmCleanup(context.Background(), v, req); e != ErrContextUnbound {
		t.Fatal("running job released", e)
	}
	if !dispatchHeld(t, q, l.Job.ID) {
		t.Fatal("dispatch freed")
	}
}

func hashLike(s string) bool { return digestPattern.MatchString(s) }

// Admission already requires start/remove to target the completed create's
// engine ID (AdmitMutation); RequiredAbsences rechecks it independently. Here a
// retargeted intent is also refused because its ID no longer matches.
func TestRequiredAbsencesRefuseRetargetedStartOrRemove(t *testing.T) {
	q, l, v, req := releasableFixture(t, true)
	s, e := q.ReconciliationSnapshot(context.Background(), v, scanevidence.ReconciliationRequest{Job: l.Job.ID, Generation: req.Generation, Challenge: strings.Repeat("f", 32)})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = scanevidence.RequiredAbsences(s.Membership); e != nil {
		t.Fatal("complete paired lifecycle refused", e)
	}
	for _, op := range []string{"remove", "start"} {
		m := s.Membership
		m.Mutations = append([]scanevidence.MutationIntent(nil), s.Membership.Mutations...)
		for i := range m.Mutations {
			if m.Mutations[i].Request.Operation == op {
				m.Mutations[i].Request.EngineID = strings.Repeat("d", 64)
			}
		}
		if _, e = scanevidence.RequiredAbsences(m); e == nil {
			t.Fatal(op + " of another engine ID accepted as proof for the created container")
		}
	}
}

func TestConfirmCleanupRefusesRevokedBindingAfterRestoreInvalidation(t *testing.T) {
	for _, statement := range []string{"UPDATE scanner_mutation_bindings SET state='revoked' WHERE state='active'", "UPDATE scanner_authorizers SET state='revoked' WHERE state='active'"} {
		q, l, v, req := releasableFixture(t, true)
		if _, e := q.S.DB.Exec(statement); e != nil {
			t.Fatal(e)
		}
		if _, e := q.ConfirmCleanup(context.Background(), v, req); e != ErrContextUnbound {
			t.Fatal("restored or withdrawn scope released a hold", statement, e)
		}
		if !dispatchHeld(t, q, l.Job.ID) {
			t.Fatal("hold freed")
		}
	}
}

func TestConfirmCleanupReplayReadableByLaterReconcilerOnSameBinding(t *testing.T) {
	q, _, v, req := releasableFixture(t, true)
	c, e := q.ConfirmCleanup(context.Background(), v, req)
	if e != nil {
		t.Fatal(e)
	}
	auth := &scannerauth.Registry{S: q.S, Now: q.Now}
	if e = auth.RevokeReconciler(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil || os.Chmod(parent, 0700) != nil {
		t.Fatal("private fixture unavailable")
	}
	next, e := auth.EnrollReconcilerFile(v.Owner, "reconciler-b", 60, v.Binding, filepath.Join(parent, "next.token"))
	if e != nil {
		t.Fatal(e)
	}
	replay, e := q.ConfirmCleanup(context.Background(), next, req)
	if e != nil || replay.Digest != c.Digest || replay.Reconciler != v.ID {
		t.Fatal("lost reply not recoverable by successor reconciler", e)
	}
}

func TestDatabaseRefusesReleaseWithoutMatchingConfirmation(t *testing.T) {
	q, l, _, req := releasableFixture(t, true)
	if _, e := q.S.DB.Exec("UPDATE scanner_allocation_generations SET state='released' WHERE job=?", l.Job.ID); e == nil {
		t.Fatal("generation released without a confirmation row")
	}
	hash := domain.Hash([]byte("x"))
	for name, row := range map[string][]any{
		"malformed":        {l.Job.ID, req.Generation, "reconciler-a", req.Membership, "x", "{}"},
		"empty-document":   {l.Job.ID, req.Generation, "reconciler-a", req.Membership, hash, "{}"},
		"other-generation": {l.Job.ID, strings.Repeat("9", 64), "reconciler-a", req.Membership, hash, `{"confirmation_digest":"` + hash + `"}`},
	} {
		if _, e := q.S.DB.Exec("INSERT INTO scanner_cleanup_confirmations(job,generation,reconciler,membership_digest,digest,document,created_at) VALUES(?,?,?,?,?,?,'2026-10-17T00:00:00Z')", row...); e == nil {
			t.Fatal("unbound confirmation row accepted:", name)
		}
	}
	if !dispatchHeld(t, q, l.Job.ID) {
		t.Fatal("hold freed")
	}
}
