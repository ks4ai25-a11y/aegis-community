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
