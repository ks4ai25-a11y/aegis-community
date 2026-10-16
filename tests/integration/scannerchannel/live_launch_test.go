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

func TestRealPrivateLiveLaunchObservationUsesCurrentBoundLease(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	engine, registry := source.Hash([]byte("example-engine")), source.Hash([]byte("example-registry"))
	if _, e := f.q.BindEngine("owner-a", engine, registry); e != nil {
		t.Fatal(e)
	}
	journal, e := f.q.BindJournal("owner-a", source.Hash([]byte("example-root")), source.Hash([]byte("example-namespace")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.q.BindBroker("owner-a", "worker-a"); e != nil {
		t.Fatal(e)
	}
	j := enqueue(t, f)
	l, e := f.client.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, file := range m.Files {
		m.Bytes += file.Size
	}
	raw, _ := json.Marshal(m)
	plan := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: engine, Workspace: "run-" + strings.Repeat("b", 32), Registry: registry, Snapshot: source.Hash(raw), Guard: f.q.Guards.AMD64, Architecture: "amd64", JournalBinding: journal.Digest, JournalNamespace: journal.Document.Namespace}
	if _, e = f.client.ReserveWorkspace(ctx, l, scanevidence.WorkspacePlan{Tool: plan.Tool, Workspace: plan.Workspace, Registry: registry, Snapshot: plan.Snapshot}); e != nil {
		t.Fatal(e)
	}
	pin := f.q.Pins["bandit"]
	if _, e = f.client.RegisterLaunch(ctx, l, plan, pin.Version, pin.Image); e != nil {
		t.Fatal(e)
	}
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(parent, 0700)
	credential := filepath.Join(parent, "observer.credential")
	v, e := f.auth.EnrollVerifierFile("owner-a", "live-observer", 5, engine, registry, credential)
	if e != nil {
		t.Fatal(e)
	}
	observer, e := workerchannel.NewVerifier(f.socket, credential, v.Owner, v.ID, engine, registry, f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer observer.Close()
	var before int64
	f.s.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&before)
	first, e := observer.LiveLaunch(ctx, plan.Container)
	if e != nil {
		t.Fatal(e)
	}
	second, e := observer.LiveLaunch(ctx, plan.Container)
	if e != nil || first.Document.Challenge == second.Document.Challenge || first.Digest == second.Digest {
		t.Fatal("new observation reused challenge", e)
	}
	if first.Document.Context.Document.Job != j.ID || first.Document.EngineAuthorized || first.Document.CleanupAuthorized || !first.Document.Live {
		t.Fatal("wrong scope or elevated authority")
	}
	var after int64
	f.s.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&after)
	if after != before {
		t.Fatal("observer renewed worker lease")
	}
	if _, e = observer.Context(ctx, j.ID); e != nil {
		t.Fatal("current revision 1.2 cleanup context rejected", e)
	}
	// Scope remains a read: expiration closes it, without releasing the slot.
	later := time.Now().Add(20 * time.Second)
	f.q.Now = func() time.Time { return later }
	if _, e = observer.LiveLaunch(ctx, plan.Container); e == nil {
		t.Fatal("expired lease still observed live")
	}
	f.q.Now = nil
	if e = f.auth.RevokeVerifier(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = observer.LiveLaunch(ctx, plan.Container); e == nil {
		t.Fatal("revoked observer retained live access")
	}
	var count int
	f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&count)
	if count != 1 {
		t.Fatal("observation released admission")
	}
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
