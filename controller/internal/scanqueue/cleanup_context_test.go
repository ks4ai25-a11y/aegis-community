// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cleanupContextFixture(t *testing.T, launch bool) (*Queue, Lease, scanevidence.LaunchPlan, *scannerauth.Registry, scanevidence.VerifierIdentity) {
	t.Helper()
	q, l, _, p := launchFixture(t)
	if launch {
		if _, e := q.RegisterLaunch(l, p); e != nil {
			t.Fatal(e)
		}
	}
	a := &scannerauth.Registry{S: q.S, Now: q.Now}
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(parent, 0700)
	v, e := a.EnrollVerifierFile(l.Job.Owner, "verifier-a", 60, p.Engine, p.Registry, filepath.Join(parent, "verifier.token"))
	if e != nil {
		t.Fatal(e)
	}
	return q, l, p, a, v
}
func TestCleanupContextAuthenticatesOriginalMetadataWithoutReleasingAdmission(t *testing.T) {
	q, l, p, a, v := cleanupContextFixture(t, true)
	ctx := context.Background()
	var before int
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&before)
	out, e := q.CleanupContext(ctx, v, l.Job.ID)
	if e != nil {
		t.Fatal(e)
	}
	d := out.Document
	if scanevidence.ValidateCleanupContext(out, v.Owner, v.ID, l.Job.ID, p.Engine, p.Registry, l.Job.LockDigest) != nil || len(d.Workspaces) != 1 || len(d.Launches) != 1 || d.Launches[0].Document.Plan != p || d.DispatchState != "active" || !d.CleanupRequired || !d.MetadataOnly || d.CleanupConfirmed || d.LeasesExcluded || d.LateStartExcluded {
		t.Fatal("context promoted cleanup")
	}
	raw, _ := json.Marshal(out)
	if len(raw) > 49<<10 || strings.Contains(string(raw), l.Token) || strings.Contains(string(raw), "token_hash") || strings.Contains(string(raw), "lease_token") || strings.Contains(string(raw), "/private/") {
		t.Fatal("private authority/path in context")
	}
	var after int
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&after)
	if before != after {
		t.Fatal("read mutated audit")
	}
	if e = q.Guard(l); e != nil {
		t.Fatal("read changed worker authority", e)
	}
	if e = a.RevokeVerifier(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = q.CleanupContext(ctx, v, l.Job.ID); !errors.Is(e, scannerauth.ErrDenied) {
		t.Fatal("revoked cached identity", e)
	}
	if e = q.Guard(l); e != nil {
		t.Fatal("verifier revoke cancelled worker", e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "active" {
		t.Fatal("read/revoke changed admission", state)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	t.Logf("VERIFIER_CONTROLLER_CONTEXT %s", raw)
}
func TestCleanupContextScopeAndExpiryDoNotBecomeWorkerAuthority(t *testing.T) {
	q, l, p, a, v := cleanupContextFixture(t, true)
	ctx := context.Background()
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(parent, 0700)
	for _, kind := range []string{"engine", "registry"} {
		engine, registry := p.Engine, p.Registry
		if kind == "engine" {
			engine = domain.Hash([]byte("other engine"))
		} else {
			registry = domain.Hash([]byte("other registry"))
		}
		wrong, e := a.EnrollVerifierFile(v.Owner, "verifier-"+kind, 1, engine, registry, filepath.Join(parent, kind))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = q.CleanupContext(ctx, wrong, l.Job.ID); !errors.Is(e, ErrContextScope) {
			t.Fatal("scope crossed", kind, e)
		}
	}
	wrong := v
	wrong.Owner = "owner-b"
	if _, e := q.CleanupContext(ctx, wrong, l.Job.ID); !errors.Is(e, scannerauth.ErrDenied) {
		t.Fatal("owner crossed", e)
	}
	if _, e := q.CleanupContext(ctx, v, domain.ID()); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("missing owned job", e)
	}
	now := q.now()
	q.Now = func() time.Time { return now.Add(61 * time.Minute) }
	if _, e := q.CleanupContext(ctx, v, l.Job.ID); !errors.Is(e, scannerauth.ErrDenied) {
		t.Fatal("expired identity", e)
	}
}
func TestCleanupContextRefusesIncompleteLegacyAndCorruptRecords(t *testing.T) {
	q, l, _, _, v := cleanupContextFixture(t, false)
	if _, e := q.CleanupContext(context.Background(), v, l.Job.ID); !errors.Is(e, ErrContextUnbound) {
		t.Fatal("workspace-only became absence", e)
	}
	for _, kind := range []string{"legacy", "guard_missing", "launch_corrupt", "workspace_corrupt", "missing_workspace", "lease_after_deadline", "wrong_guard_set", "unknown_tool"} {
		t.Run(kind, func(t *testing.T) {
			q, l, _, _, v := cleanupContextFixture(t, true)
			switch kind {
			case "legacy":
				q.S.DB.Exec("UPDATE scanner_dispatch SET launch_protocol=0")
			case "guard_missing":
				q.S.DB.Exec("UPDATE scanner_dispatch SET guard_set_digest=''")
			case "launch_corrupt":
				q.S.DB.Exec("DROP TRIGGER scanner_launches_no_update")
				q.S.DB.Exec("UPDATE scanner_launches SET document='{}'")
			case "workspace_corrupt":
				q.S.DB.Exec("DROP TRIGGER scanner_workspaces_no_update")
				q.S.DB.Exec("UPDATE scanner_workspaces SET document='{}'")
			case "missing_workspace":
				q.S.DB.Exec("DROP TRIGGER scanner_workspaces_no_delete")
				q.S.DB.Exec("DELETE FROM scanner_workspaces")
			case "lease_after_deadline":
				q.S.DB.Exec("UPDATE scanner_dispatch SET lease_until=deadline+1")
			case "wrong_guard_set":
				q.S.DB.Exec("UPDATE scanner_dispatch SET guard_set_digest=?", domain.Hash([]byte("other set")))
			case "unknown_tool":
				q.S.DB.Exec("DROP TRIGGER scanner_workspaces_no_update")
				q.S.DB.Exec("UPDATE scanner_workspaces SET tool='syft'")
			}
			if _, e := q.CleanupContext(context.Background(), v, l.Job.ID); e == nil {
				t.Fatal("unsafe metadata returned")
			}
		})
	}
}
func TestCleanupContextPreservesCancellationAndOriginalDeadline(t *testing.T) {
	q, l, _, _, v := cleanupContextFixture(t, true)
	before, e := q.CleanupContext(context.Background(), v, l.Job.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Cancel(l.Job.Owner, l.Job.ID); e != nil {
		t.Fatal(e)
	}
	pending, e := q.CleanupContext(context.Background(), v, l.Job.ID)
	if e != nil || !pending.Document.CancelRequested || pending.Document.JobState != "running" || pending.Document.CleanupConfirmed {
		t.Fatal("pending cancellation lost", e)
	}
	now := q.now()
	q.Now = func() time.Time { return now.Add(20 * time.Second) }
	if e = q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	after, e := q.CleanupContext(context.Background(), v, l.Job.ID)
	if e != nil || after.Document.JobState != "cancelled" || after.Document.DispatchState != "cleanup_required" || after.Document.Deadline != before.Document.Deadline || !after.Document.CleanupRequired || after.Document.CleanupConfirmed {
		t.Fatal(after, e)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = q.CleanupContext(cancelled, v, l.Job.ID); e == nil {
		t.Fatal("cancelled read succeeded")
	}
}
