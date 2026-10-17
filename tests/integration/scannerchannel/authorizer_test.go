//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/alpha/workerchannel"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupAuthorizerProtocol(t *testing.T) (fixture, *workerchannel.AuthorizerClient, scanevidence.AuthorizerIdentity, scanevidence.AuthorizerLaunch) {
	t.Helper()
	f := setup(t)
	ctx := context.Background()
	engine, registry, policy, namespace := source.Hash([]byte("synthetic engine")), source.Hash([]byte("synthetic registry")), source.Hash([]byte("synthetic policy")), source.Hash([]byte("synthetic protocol2 namespace"))
	if _, e := f.q.BindEngine("owner-a", engine, registry); e != nil {
		t.Fatal(e)
	}
	journal, e := f.q.BindJournal("owner-a", source.Hash([]byte("synthetic journal root")), source.Hash([]byte("synthetic journal namespace")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.q.BindBroker("owner-a", "worker-a"); e != nil {
		t.Fatal(e)
	}
	credential := filepath.Join(filepath.Dir(f.credential), "authorizer.credential")
	v, e := f.auth.EnrollAuthorizerFile("owner-a", "authorizer-a", 5, engine, registry, policy, credential)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.q.BindMutationAuthorizer(v.Owner, v.ID, namespace); e != nil {
		t.Fatal(e)
	}
	enqueue(t, f)
	l, e := f.client.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, file := range m.Files {
		m.Bytes += file.Size
	}
	raw, _ := json.Marshal(m)
	p := scanevidence.LaunchPlan{Tool: "bandit", Container: gateName, Engine: engine, Registry: registry, Workspace: "run-" + strings.Repeat("b", 32), Snapshot: source.Hash(raw), Guard: f.q.Guards.AMD64, Architecture: "amd64", JournalBinding: journal.Digest, JournalNamespace: journal.Document.Namespace}
	if _, e = f.client.ReserveWorkspace(ctx, l, scanevidence.WorkspacePlan{Tool: p.Tool, Workspace: p.Workspace, Registry: p.Registry, Snapshot: p.Snapshot}); e != nil {
		t.Fatal(e)
	}
	pin := f.q.Pins[p.Tool]
	if _, e = f.client.RegisterLaunch(ctx, l, p, pin.Version, pin.Image); e != nil {
		t.Fatal(e)
	}
	client, e := workerchannel.NewAuthorizer(f.socket, credential, v.Owner, v.ID, engine, registry, policy, namespace, f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	d, e := client.Launch(ctx, gateName, "create")
	if e != nil {
		t.Fatal(e)
	}
	return f, client, v, d
}
func TestActualUnixAuthorizerAdmitsAndConfirmsWithoutReleasing(t *testing.T) {
	f, c, v, d := setupAuthorizerProtocol(t)
	ctx := context.Background()
	b, e := c.Binding(ctx)
	if e != nil || b.Digest != d.Binding.Digest {
		t.Fatal("selected binding mismatch", e)
	}
	raw, _ := json.Marshal(d)
	workerToken, _ := os.ReadFile(f.credential)
	for _, secret := range []string{strings.TrimSpace(string(workerToken)), "token_hash", "lease_token", "/private/"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private capability in metadata")
		}
	}
	a, e := c.Admit(ctx, d, source.Hash([]byte("create request")), "")
	if e != nil || a.Replay {
		t.Fatal("new create admission failed", e)
	}
	again, e := c.Admit(ctx, d, source.Hash([]byte("create request")), "")
	if e != nil || !again.Replay || again.Intent != a.Intent {
		t.Fatal("admission replay changed", e)
	}
	complete := func(a scanevidence.MutationAdmission, status int) {
		t.Helper()
		in := scanevidence.MutationCompletion{Intent: a.Intent.ID, Generation: d.Generation.ID, Status: status, EngineID: gateID, Response: source.Hash([]byte("local durable " + a.Intent.Request.Operation))}
		if _, e = c.Complete(ctx, in); e != nil {
			t.Fatal(e)
		}
		if _, e = c.Complete(ctx, in); e != nil {
			t.Fatal("completion replay failed", e)
		}
	}
	complete(a, 201)
	start, e := c.Launch(ctx, gateName, "start")
	if e != nil {
		t.Fatal(e)
	}
	a, e = c.Admit(ctx, start, source.Hash([]byte("start request")), gateID)
	if e != nil {
		t.Fatal(e)
	}
	complete(a, 204)
	if e = f.q.Cancel(v.Owner, d.Generation.Job); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Launch(ctx, gateName, "start"); e == nil {
		t.Fatal("closed generation exposed live start")
	}
	remove, e := c.Launch(ctx, gateName, "remove")
	if e != nil {
		t.Fatal(e)
	}
	a, e = c.Admit(ctx, remove, source.Hash([]byte("remove request")), gateID)
	if e != nil {
		t.Fatal(e)
	}
	complete(a, 204)
	if _, e = f.s.DB.Exec("DELETE FROM scanner_dispatch"); e == nil {
		t.Fatal("authorizer responses released dispatch")
	}
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestActualUnixAuthorizerRefusesOtherRolesAndWrongSelection(t *testing.T) {
	f, c, v, d := setupAuthorizerProtocol(t)
	ctx := context.Background()
	dir := filepath.Dir(f.credential)
	observer := filepath.Join(dir, "observer.credential")
	if _, e := f.auth.EnrollVerifierFile(v.Owner, "observer-a", 5, v.Engine, v.Registry, observer); e != nil {
		t.Fatal(e)
	}
	for _, credential := range []string{f.credential, observer} {
		other, e := workerchannel.NewAuthorizer(f.socket, credential, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, d.Binding.Document.Namespace, f.q.LockDigest)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = other.Identity(ctx); e == nil {
			t.Fatal("another role acquired identity")
		}
		if _, e = other.Admit(ctx, d, source.Hash([]byte("descriptor")), ""); e == nil {
			t.Fatal("another role admitted mutation")
		}
		other.Close()
	}
	credential := filepath.Join(dir, "authorizer.credential")
	wrong, e := workerchannel.NewAuthorizer(f.socket, credential, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, source.Hash([]byte("wrong namespace")), f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.Binding(ctx); e == nil {
		t.Fatal("wrong namespace accepted selected binding")
	}
	if _, e = wrong.Launch(ctx, gateName, "create"); e == nil {
		t.Fatal("wrong namespace accepted launch")
	}
	if e = f.auth.RevokeAuthorizer(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Admit(ctx, d, source.Hash([]byte("descriptor")), ""); e == nil {
		t.Fatal("revoked authorizer admitted mutation")
	}
	var n int
	if e = f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 0 {
		t.Fatal("denial created intent", e)
	}
}

func TestAuthorizerLaunchMetadataRejectsChangedMembershipAndAuthority(t *testing.T) {
	f, _, v, original := setupAuthorizerProtocol(t)
	r := scanevidence.AuthorizerLaunchRequest{Container: gateName, Challenge: original.Challenge, Operation: "create"}
	for _, kind := range []string{"challenge", "flags", "binding", "namespace", "generation", "workspace", "map", "launch", "guard", "deadline", "scope"} {
		d := original
		caller := v
		switch kind {
		case "challenge":
			d.Challenge = strings.Repeat("f", 32)
		case "flags":
			d.EngineAuthorized = true
		case "binding":
			d.Binding.Digest = source.Hash([]byte("different binding"))
		case "namespace":
			d.Binding.Document.Namespace = source.Hash([]byte("different namespace"))
		case "generation":
			d.Generation.ID = "invalid"
		case "workspace":
			d.Workspace.Document.Plan.Workspace = "run-" + strings.Repeat("d", 32)
		case "map":
			d.Workspace.Document.Map = source.Hash([]byte("changed map"))
		case "launch":
			d.Launch.Document.Plan.Container = "aegis-scan-" + strings.Repeat("d", 32)
		case "guard":
			d.Guards.Digest = source.Hash([]byte("wrong guard"))
		case "deadline":
			d.Generation.Deadline++
		case "scope":
			caller.Role = scanevidence.CleanupObserverRole
		}
		if d.Valid(caller, original.Binding.Document.Namespace, f.q.LockDigest, r, time.Now()) {
			t.Fatal("changed authority/membership accepted", kind)
		}
	}
}
