// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
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

func liveLaunchFixture(t *testing.T) (*Queue, Lease, scanevidence.LaunchPlan, *scannerauth.Registry, scanevidence.VerifierIdentity) {
	t.Helper()
	q, in, _ := fixture(t)
	_, journal := provisionJournalFixture(t, q)
	if _, e := q.BindBroker("owner-a", "trusted-worker"); e != nil {
		t.Fatal(e)
	}
	in.Tools = []string{"bandit"}
	q.Pins = map[string]Pin{"bandit": {"1.9.4", domain.Hash([]byte("image"))}}
	l := enqueueClaim(t, q, in)
	m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range m.Files {
		m.Bytes += f.Size
	}
	m.Digest = domain.Digest(m)
	p := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: domain.Hash([]byte("engine")), Registry: domain.Hash([]byte("registry")), Workspace: "run-" + strings.Repeat("a", 32), Snapshot: m.Digest, Guard: q.Guards.AMD64, Architecture: "amd64", JournalBinding: journal.Digest, JournalNamespace: journal.Document.Namespace}
	reserveLaunchWorkspace(t, q, l, p)
	if _, e := q.RegisterLaunch(l, p); e != nil {
		t.Fatal(e)
	}
	auth := &scannerauth.Registry{S: q.S, Now: q.Now}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	v, e := auth.EnrollVerifierFile(l.Job.Owner, "observer-a", 60, p.Engine, p.Registry, filepath.Join(dir, "observer.credential"))
	if e != nil {
		t.Fatal(e)
	}
	return q, l, p, auth, v
}
func TestLiveLaunchReadBindsCurrentScopeWithoutRenewalOrAuthority(t *testing.T) {
	q, l, p, _, v := liveLaunchFixture(t)
	ctx := context.Background()
	nonce := strings.Repeat("b", 32)
	var beforeLease, beforeAudit int64
	q.S.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&beforeLease)
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&beforeAudit)
	out, e := q.LiveLaunch(ctx, v, p.Container, nonce)
	if e != nil {
		t.Fatal(e)
	}
	if scanevidence.ValidateLiveLaunch(out, v.Owner, v.ID, p.Container, nonce, p.Engine, p.Registry, l.Job.LockDigest) != nil || out.Document.EngineAuthorized || out.Document.CleanupAuthorized {
		t.Fatal("invalid or inflated observation")
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{l.Token, "token_hash", "lease_token", "/private/"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("secret or path in metadata")
		}
	}
	var afterLease, afterAudit int64
	q.S.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&afterLease)
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&afterAudit)
	if beforeLease != afterLease || beforeAudit != afterAudit {
		t.Fatal("read renewed lease or wrote audit")
	}
	if _, e = q.CleanupContext(ctx, v, l.Job.ID); e != nil {
		t.Fatal("bound launch revision 1.2 context refused", e)
	}
	again, e := q.LiveLaunch(ctx, v, p.Container, strings.Repeat("c", 32))
	if e != nil || again.Digest == out.Digest {
		t.Fatal("request challenge not bound")
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestLiveLaunchRefusesStaleRevokedCancelledAndUnboundState(t *testing.T) {
	for _, kind := range []string{"lease-expired", "deadline", "cancel", "job-terminal", "dispatch-held", "worker-revoked", "worker-expired", "observer-revoked", "observer-expired", "wrong-owner", "wrong-engine", "wrong-registry", "unknown-container", "bad-challenge", "guard-rotated", "lock-rotated", "engine-missing", "journal-missing", "broker-missing", "broker-corrupt", "map-changed", "cancelled-context"} {
		t.Run(kind, func(t *testing.T) {
			q, l, p, auth, v := liveLaunchFixture(t)
			name, challenge := p.Container, strings.Repeat("b", 32)
			ctx := context.Background()
			switch kind {
			case "lease-expired":
				q.S.DB.Exec("UPDATE scanner_dispatch SET lease_until=?", q.now().Unix())
			case "deadline":
				q.S.DB.Exec("UPDATE scanner_dispatch SET deadline=?", q.now().Unix())
			case "cancel":
				q.S.DB.Exec("UPDATE scanner_jobs SET cancel_requested=1")
			case "job-terminal":
				q.S.DB.Exec("UPDATE scanner_jobs SET state='tool_error'")
			case "dispatch-held":
				q.S.DB.Exec("UPDATE scanner_dispatch SET state='cleanup_required'")
			case "worker-revoked":
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked'")
			case "worker-expired":
				q.S.DB.Exec("UPDATE scanner_workers SET expires=?", q.now().Unix())
			case "observer-revoked":
				if e := auth.RevokeVerifier(v.Owner, v.ID); e != nil {
					t.Fatal(e)
				}
			case "observer-expired":
				base := q.now()
				q.Now = func() time.Time { return base.Add(61 * time.Minute) }
			case "wrong-owner":
				v.Owner = "owner-b"
			case "wrong-engine":
				v.Engine = domain.Hash([]byte("other-engine"))
			case "wrong-registry":
				v.Registry = domain.Hash([]byte("other-registry"))
			case "unknown-container":
				name = "aegis-scan-" + strings.Repeat("d", 32)
			case "bad-challenge":
				challenge = "invalid"
			case "guard-rotated":
				q.Guards.Digest = domain.Hash([]byte("rotated"))
			case "lock-rotated":
				q.LockDigest = domain.Hash([]byte("rotated"))
			case "engine-missing":
				q.S.DB.Exec("DELETE FROM settings WHERE key=?", engineBindingKey)
			case "journal-missing":
				q.S.DB.Exec("DELETE FROM settings WHERE key=?", journalBindingKey)
			case "broker-missing":
				q.S.DB.Exec("DELETE FROM settings WHERE key=?", brokerBindingKey)
			case "broker-corrupt":
				q.S.DB.Exec("UPDATE settings SET value='{}' WHERE key=?", brokerBindingKey)
			case "map-changed":
				q.S.DB.Exec("UPDATE repositories SET map_digest=?", domain.Hash([]byte("changed")))
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, e := q.LiveLaunch(ctx, v, name, challenge); e == nil {
				t.Fatal("invalid live state accepted")
			}
			var count int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&count)
			if count != 1 {
				t.Fatal("read released admission")
			}
			_ = l
		})
	}
}
func TestLiveLaunchRequiresFullyBoundRevisionAndLatestTime(t *testing.T) {
	q, l, p, auth, v := cleanupContextFixture(t, true)
	if _, e := q.LiveLaunch(context.Background(), v, p.Container, strings.Repeat("b", 32)); e == nil {
		t.Fatal("legacy launch became live bound scope")
	}
	_ = l
	_ = auth
	q2, _, p2, _, v2 := liveLaunchFixture(t)
	base := q2.now()
	calls := 0
	q2.Now = func() time.Time {
		calls++
		if calls > 5 {
			return base.Add(time.Minute)
		}
		return base
	}
	if _, e := q2.LiveLaunch(context.Background(), v2, p2.Container, strings.Repeat("b", 32)); e == nil {
		t.Fatal("lease expired while reading but was accepted")
	}
}
