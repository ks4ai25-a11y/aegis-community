// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enrollReconciliationFixture(t *testing.T, q *Queue, b MutationBinding) scanevidence.ReconcilerIdentity {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(parent, 0700) != nil {
		t.Fatal("private fixture unavailable")
	}
	v, err := (&scannerauth.Registry{S: q.S, Now: q.Now}).EnrollReconcilerFile(b.Owner, "reconciler-a", 60, b.Digest, filepath.Join(parent, "reconciler.token"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func reconciliationRequest(l Lease, r MutationRequest) scanevidence.ReconciliationRequest {
	return scanevidence.ReconciliationRequest{Job: l.Job.ID, Generation: r.Generation, Challenge: strings.Repeat("d", 32)}
}

func TestReconciliationSnapshotRetainsPendingMembershipAndNeverReleases(t *testing.T) {
	q, l, authorizer, r, b := mutationFixture(t)
	v := enrollReconciliationFixture(t, q, b)
	req := reconciliationRequest(l, r)
	if _, err := q.ReconciliationSnapshot(context.Background(), v, req); err != ErrContextUnbound {
		t.Fatal("open generation acquired reconciliation context", err)
	}
	intent := mustAdmit(t, q, authorizer, r)
	if err := q.Cancel(l.Job.Owner, l.Job.ID); err != nil {
		t.Fatal(err)
	}
	var beforeDispatch string
	if err := q.S.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job=?", l.Job.ID).Scan(&beforeDispatch); err != nil {
		t.Fatal(err)
	}
	var auditsBefore, auditsAfter int
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&auditsBefore)
	s, err := q.ReconciliationSnapshot(context.Background(), v, req)
	if err != nil {
		t.Fatal("closed snapshot unavailable", err)
	}
	if !scanevidence.ValidateReconciliationSnapshot(s, v, req, q.now()) || len(s.Membership.Workspaces) != 1 || len(s.Membership.Launches) != 1 || len(s.Membership.Mutations) != 1 || s.Membership.Mutations[0] != intent || s.CleanupReleased || s.EngineWrites || !s.CleanupRequired {
		t.Fatal("pending snapshot lost membership or invented authority")
	}
	encoded, err := json.Marshal(s)
	if err != nil || strings.Contains(string(encoded), l.Token) || strings.Contains(string(encoded), domain.Hash([]byte(l.Token))) {
		t.Fatal("snapshot exposed lease capability")
	}
	decoded, err := scanevidence.DecodeReconciliationSnapshot(encoded)
	if err != nil || !scanevidence.ValidateReconciliationSnapshot(decoded, v, req, q.now()) {
		t.Fatal("snapshot canonical round trip failed", err)
	}
	changed := s
	changed.Membership.Tools = append([]string(nil), s.Membership.Tools...)
	changed.Membership.Mutations = append([]scanevidence.MutationIntent(nil), s.Membership.Mutations...)
	changed.Membership.Mutations[0].Response = domain.Hash([]byte("false response"))
	if scanevidence.ValidateReconciliationSnapshot(changed, v, req, q.now()) {
		t.Fatal("tampered pending response accepted")
	}
	completed := mustComplete(t, q, authorizer, intent)
	next, err := q.ReconciliationSnapshot(context.Background(), v, req)
	if err != nil || next.MembershipHash == s.MembershipHash || next.Membership.Mutations[0].Response != completed.Response {
		t.Fatal("completion did not change membership identity", err)
	}
	req.Challenge = strings.Repeat("e", 32)
	fresh, err := q.ReconciliationSnapshot(context.Background(), v, req)
	if err != nil || fresh.MembershipHash != next.MembershipHash || fresh.Challenge == next.Challenge {
		t.Fatal("fresh challenge changed stable membership", err)
	}
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&auditsAfter)
	// Exactly the explicit completion above audited a write; metadata reads did not.
	if auditsAfter != auditsBefore+1 {
		t.Fatal("metadata read changed audit history")
	}
	var state string
	if err = q.S.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job=?", l.Job.ID).Scan(&state); err != nil || state != beforeDispatch {
		t.Fatal("snapshot freed held dispatch", err)
	}
	if _, err = q.S.DB.Exec("DELETE FROM scanner_dispatch WHERE job=?", l.Job.ID); err == nil {
		t.Fatal("snapshot authorized dispatch deletion")
	}
}

func TestReconciliationSnapshotRefusesWrongScopeWithoutChangingState(t *testing.T) {
	for _, kind := range []string{"owner", "reconciler", "role", "binding", "engine", "registry", "policy", "namespace", "generation", "job", "challenge", "revoked", "expired", "dispatch-hash", "cancelled-context"} {
		t.Run(kind, func(t *testing.T) {
			q, l, _, r, b := mutationFixture(t)
			v := enrollReconciliationFixture(t, q, b)
			if err := q.Cancel(l.Job.Owner, l.Job.ID); err != nil {
				t.Fatal(err)
			}
			var beforeDispatch string
			if err := q.S.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job=?", l.Job.ID).Scan(&beforeDispatch); err != nil {
				t.Fatal(err)
			}
			req := reconciliationRequest(l, r)
			ctx := context.Background()
			switch kind {
			case "owner":
				v.Owner = "owner-b"
			case "reconciler":
				v.ID = "another-reconciler"
			case "role":
				v.Role = scanevidence.CleanupObserverRole
			case "binding":
				v.Binding = domain.Hash([]byte("other"))
			case "engine":
				v.Engine = domain.Hash([]byte("other"))
			case "registry":
				v.Registry = domain.Hash([]byte("other"))
			case "policy":
				v.Policy = domain.Hash([]byte("other"))
			case "namespace":
				v.Namespace = domain.Hash([]byte("other"))
			case "generation":
				req.Generation = strings.Repeat("f", 64)
			case "job":
				req.Job = domain.ID()
			case "challenge":
				req.Challenge = "short"
			case "revoked":
				if err := (&scannerauth.Registry{S: q.S, Now: q.Now}).RevokeReconciler(v.Owner, v.ID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				now := q.now().Add(time.Hour)
				q.Now = func() time.Time { return now }
			case "dispatch-hash":
				if _, err := q.S.DB.Exec("UPDATE scanner_dispatch SET token_hash=?", domain.Hash([]byte("different"))); err != nil {
					t.Fatal(err)
				}
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := q.ReconciliationSnapshot(ctx, v, req); err == nil {
				t.Fatal("wrong scope received reconciliation membership")
			}
			var state string
			if err := q.S.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job=?", l.Job.ID).Scan(&state); err != nil || state != beforeDispatch {
				t.Fatal("refused read changed cleanup hold", err)
			}
		})
	}
}

func TestReconciliationSnapshotReadsOriginalRevokedScopeAndTracksNewRemoval(t *testing.T) {
	q, l, authorizer, r, b := mutationFixture(t)
	v := enrollReconciliationFixture(t, q, b)
	created := mustAdmit(t, q, authorizer, r)
	confirmation := mustComplete(t, q, authorizer, created)
	if err := q.Cancel(l.Job.Owner, l.Job.ID); err != nil {
		t.Fatal(err)
	}
	req := reconciliationRequest(l, r)
	first, err := q.ReconciliationSnapshot(context.Background(), v, req)
	if err != nil {
		t.Fatal(err)
	}
	remove := r
	remove.Operation = "remove"
	remove.EngineID = confirmation.EngineID
	remove.Descriptor = domain.Hash([]byte("remove"))
	intent := mustAdmit(t, q, authorizer, remove)
	next, err := q.ReconciliationSnapshot(context.Background(), v, req)
	if err != nil || first.MembershipHash == next.MembershipHash || len(next.Membership.Mutations) != 2 {
		t.Fatal("new cleanup obligation was omitted", err)
	}
	mustComplete(t, q, authorizer, intent)
	if err = (&scannerauth.Registry{S: q.S, Now: q.Now}).RevokeAuthorizer(authorizer.Owner, authorizer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = q.S.DB.Exec("DELETE FROM settings WHERE key IN ('scanner_engine_binding','scanner_engine_journal_binding','scanner_engine_broker_binding')"); err != nil {
		t.Fatal(err)
	}
	q.Guards = scanevidence.GuardSet{}
	retained, err := q.ReconciliationSnapshot(context.Background(), v, req)
	if err != nil || retained.Membership.Binding.Digest != b.Digest || retained.CleanupReleased || retained.EngineWrites {
		t.Fatal("original retained scope depended on new live approvals", err)
	}
}
