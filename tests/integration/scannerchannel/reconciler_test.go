//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/alpha/workerchannel"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconcilerPrivateUnixMembershipAndRoleIsolation(t *testing.T) {
	f, authorizer, identity, launch := setupAuthorizerProtocol(t)
	ctx := context.Background()
	admitted, err := authorizer.Admit(ctx, launch, source.Hash([]byte("fixed synthetic create request")), "")
	if err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(filepath.Dir(f.credential), "reconciler.credential")
	v, err := f.auth.EnrollReconcilerFile(identity.Owner, "reconciler-a", 5, launch.Binding.Digest, credential)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.q.Cancel(identity.Owner, launch.Generation.Job); err != nil {
		t.Fatal(err)
	}
	client, err := workerchannel.NewReconciler(f.socket, credential, v.Owner, v.ID, v.Binding, v.Engine, v.Registry, v.Policy, v.Namespace, f.q.LockDigest)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got, err := client.Identity(ctx)
	if err != nil || got != v {
		t.Fatal("reconciler identity scope changed", err)
	}
	first, err := client.Snapshot(ctx, launch.Generation.Job, launch.Generation.ID)
	if err != nil || len(first.Membership.Mutations) != 1 || first.Membership.Mutations[0] != admitted.Intent || !first.MetadataOnly || !first.CleanupRequired || first.CleanupReleased || first.EngineWrites {
		t.Fatal("private pending membership lost scope or gained authority", err)
	}
	again, err := client.Snapshot(ctx, launch.Generation.Job, launch.Generation.ID)
	if err != nil || again.MembershipHash != first.MembershipHash || again.Challenge == first.Challenge {
		t.Fatal("fresh request changed stable membership or reused nonce", err)
	}
	if _, err = authorizer.Complete(ctx, scanevidence.MutationCompletion{Intent: admitted.Intent.ID, Generation: launch.Generation.ID, Status: 201, EngineID: strings.Repeat("c", 64), Response: source.Hash([]byte("fixed synthetic native response"))}); err != nil {
		t.Fatal(err)
	}
	completed, err := client.Snapshot(ctx, launch.Generation.Job, launch.Generation.ID)
	if err != nil || completed.MembershipHash == first.MembershipHash || completed.Membership.Mutations[0].State != "completed" || completed.CleanupReleased {
		t.Fatal("completed membership failed to invalidate old observation", err)
	}
	for _, path := range []string{f.credential, filepath.Join(filepath.Dir(f.credential), "authorizer.credential")} {
		other, err := workerchannel.NewReconciler(f.socket, path, v.Owner, v.ID, v.Binding, v.Engine, v.Registry, v.Policy, v.Namespace, f.q.LockDigest)
		if err != nil {
			t.Fatal(err)
		}
		_, err = other.Identity(ctx)
		other.Close()
		if err == nil {
			t.Fatal("another credential acquired reconciler authority")
		}
	}
	worker, err := workerchannel.New(f.socket, credential, v.Owner, f.q.LockDigest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = worker.Identity(ctx)
	worker.Close()
	if err == nil {
		t.Fatal("reconciler acquired worker authority")
	}
	if err = f.auth.RevokeReconciler(v.Owner, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Snapshot(ctx, launch.Generation.Job, launch.Generation.ID); err == nil {
		t.Fatal("revoked role reused cached Unix connection")
	}
	var held int
	if err = f.q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch WHERE job=?", launch.Generation.Job).Scan(&held); err != nil || held != 1 {
		t.Fatal("read context released allocation", err)
	}
}
