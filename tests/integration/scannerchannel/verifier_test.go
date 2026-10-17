// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package scannerchannelacceptance

import (
	"aegis.local/alpha/workerchannel"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the separate role against the same real private listener and ledger
// used by producer clients. Reading metadata cannot complete host cleanup.
func assertScopedVerifierContext(t *testing.T, f fixture, job string) {
	t.Helper()
	launches, e := f.q.Launches("owner-a", job)
	if e != nil || len(launches) == 0 {
		t.Fatal("fixture has no bound launch", e)
	}
	p := launches[0].Document.Plan
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(parent, 0700)
	credential := filepath.Join(parent, "verifier.credential")
	v, e := f.auth.EnrollVerifierFile("owner-a", "verifier-test", 5, p.Engine, p.Registry, credential)
	if e != nil {
		t.Fatal(e)
	}
	client, e := workerchannel.NewVerifier(f.socket, credential, v.Owner, v.ID, v.Engine, v.Registry, f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	observed, e := client.Context(ctx, job)
	if e != nil {
		t.Fatal("actual private verifier context failed", e)
	}
	if scanevidence.ValidateCleanupContext(observed, v.Owner, v.ID, job, p.Engine, p.Registry, f.q.LockDigest) != nil || observed.Document.DispatchState != "cleanup_required" || observed.Document.CleanupConfirmed || observed.Document.LeasesExcluded || observed.Document.LateStartExcluded || !observed.Document.MetadataOnly {
		t.Fatal("metadata promoted to resource proof")
	}
	worker, e := workerchannel.New(f.socket, credential, v.Owner, f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer worker.Close()
	if _, e = worker.Claim(ctx); e == nil {
		t.Fatal("verifier claimed execution")
	}
	wrong, e := workerchannel.NewVerifier(f.socket, f.credential, v.Owner, v.ID, v.Engine, v.Registry, f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.Identity(ctx); e == nil {
		t.Fatal("worker acquired verifier authority")
	}
	changed, e := workerchannel.NewVerifier(f.socket, credential, v.Owner, v.ID, source.Hash([]byte("other engine")), v.Registry, f.q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer changed.Close()
	if _, e = changed.Context(ctx, job); e == nil {
		t.Fatal("client accepted changed scope")
	}
	b, _ := json.Marshal(observed)
	if strings.Contains(string(b), "lease_token") || strings.Contains(string(b), "token_hash") {
		t.Fatal("private capability in context")
	}
	t.Logf("VERIFIER_PRIVATE_IDENTITY %s", mustJSONVerifier(v))
	t.Logf("VERIFIER_PRIVATE_CONTEXT %s", b)
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") == "1" {
		root, _ := filepath.Abs("../../..")
		root, _ = filepath.EvalSymlinks(root)
		cmd := exec.CommandContext(ctx, filepath.Join(root, "bin/aegis-research"), "verifier-context", f.socket, credential, v.Owner, v.ID, v.Engine, v.Registry, root, job)
		output, e := cmd.Output()
		if e != nil || len(output) > 64<<10 {
			t.Fatal("native verifier CLI failed", e)
		}
		var got scanevidence.CleanupContextRecord
		if json.Unmarshal(output, &got) != nil || scanevidence.ValidateCleanupContext(got, v.Owner, v.ID, job, v.Engine, v.Registry, f.q.LockDigest) != nil {
			t.Fatal("native verifier CLI detached scope")
		}
		t.Logf("VERIFIER_NATIVE_CLI_CONTEXT %s", strings.TrimSpace(string(output)))
	}
	if e = f.auth.RevokeVerifier(v.Owner, v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Context(ctx, job); e == nil {
		t.Fatal("revoked verifier context accepted")
	}
	assertCleanupHeld(t, f)
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func mustJSONVerifier(v any) string { b, _ := json.Marshal(v); return string(b) }
