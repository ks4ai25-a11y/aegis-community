//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package recovery

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixture(t *testing.T) (Config, *store.Store, string) {
	t.Helper()
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s, e := store.Open(filepath.Join(parent, "source.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	p, _, e := s.Active()
	if e != nil {
		t.Fatal(e)
	}
	gateway := filepath.Join(parent, "active.Caddyfile")
	if e = os.WriteFile(gateway, gatewayBytes(p), 0600); e != nil {
		t.Fatal(e)
	}
	lock, e := filepath.Abs("../../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	lock, e = filepath.EvalSymlinks(lock)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Set("history-marker", "private-retained-marker"); e != nil {
		t.Fatal(e)
	}
	if e = s.Audit("owner", "fixture.created", "fixture", "OK", nil); e != nil {
		t.Fatal(e)
	}
	return Config{Database: s.Path, Gateway: gateway, ToolLock: lock}, s, parent
}
func makeBundle(t *testing.T, c Config, parent string) (string, Receipt) {
	t.Helper()
	path := filepath.Join(parent, "bundle")
	r, e := Create(context.Background(), c, path)
	if e != nil {
		t.Fatal(e)
	}
	return path, r
}
func TestBundleCapturesMatchingPolicyToolAndDatabaseWithoutActivating(t *testing.T) {
	c, s, parent := fixture(t)
	path, created := makeBundle(t, c, parent)
	checked, e := Verify(context.Background(), c, path)
	if e != nil || checked.Bundle != created.Bundle || !checked.Integrity || checked.RestoreVerified || checked.Activated || checked.Signature {
		t.Fatal(checked, e)
	}
	for _, name := range []string{"state.db", "manifest.json", "scanners.lock.json", "active.Caddyfile", ".lock"} {
		info, e := os.Lstat(filepath.Join(path, name))
		if e != nil || !owned(info, 0600, false) {
			t.Fatal("nonprivate bundle", name, e)
		}
	}
	if _, e = Create(context.Background(), c, path); e == nil {
		t.Fatal("existing bundle replaced")
	}
	if value, e := s.Get("history-marker"); e != nil || value != "private-retained-marker" {
		t.Fatal("source changed")
	}
	encoded, _ := json.Marshal(checked)
	if bytes.Contains(encoded, []byte(parent)) || bytes.Contains(encoded, []byte("private-retained-marker")) {
		t.Fatal("receipt exposed source")
	}
}
func TestBundleRefusesPolicyDriftInflightActivationAuditTamperAndToolChanges(t *testing.T) {
	for _, kind := range []string{"gateway", "inflight", "audit", "unknown_schema", "tool_tag", "duplicate_tool"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			switch kind {
			case "gateway":
				os.WriteFile(c.Gateway, []byte("mismatched gateway"), 0600)
			case "inflight":
				s.Set("apply_journal", domain.Hash([]byte("unfinished")))
			case "audit":
				s.DB.Exec("UPDATE audit SET document='{}' WHERE seq=1")
			case "unknown_schema":
				s.DB.Exec("INSERT INTO migrations VALUES(99,'unknown')")
			case "tool_tag", "duplicate_tool":
				data, e := os.ReadFile(c.ToolLock)
				if e != nil {
					t.Fatal(e)
				}
				var lock map[string]any
				json.Unmarshal(data, &lock)
				tools := lock["tools"].([]any)
				if kind == "tool_tag" {
					tools[0].(map[string]any)["image"] = "semgrep/semgrep:latest"
				} else {
					tools[1] = tools[0]
				}
				data, _ = json.Marshal(lock)
				c.ToolLock = filepath.Join(parent, "invalid-lock.json")
				os.WriteFile(c.ToolLock, data, 0600)
			}
			path := filepath.Join(parent, "refused")
			if _, e := Create(context.Background(), c, path); e == nil {
				t.Fatal("inconsistent bundle created")
			}
			if _, e := os.Lstat(path); !os.IsNotExist(e) {
				t.Fatal("failed bundle published")
			}
		})
	}
}
func TestBundleVerificationRefusesCorruptionUnknownFilesAndUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"database", "manifest", "gateway", "tool_lock", "extra", "symlink", "fifo", "hardlink", "public", "missing_lock"} {
		t.Run(kind, func(t *testing.T) {
			c, _, parent := fixture(t)
			path, _ := makeBundle(t, c, parent)
			switch kind {
			case "database":
				os.WriteFile(filepath.Join(path, "state.db"), []byte("torn"), 0600)
			case "manifest":
				os.WriteFile(filepath.Join(path, "manifest.json"), []byte("{}"), 0600)
			case "gateway":
				os.WriteFile(filepath.Join(path, "active.Caddyfile"), []byte("changed"), 0600)
			case "tool_lock":
				os.WriteFile(filepath.Join(path, "scanners.lock.json"), []byte("{}"), 0600)
			case "extra":
				os.WriteFile(filepath.Join(path, "unknown"), nil, 0600)
			case "public":
				os.Chmod(path, 0755)
			case "missing_lock":
				os.Remove(filepath.Join(path, ".lock"))
			case "symlink", "fifo", "hardlink":
				p := filepath.Join(path, "active.Caddyfile")
				os.Remove(p)
				var e error
				if kind == "symlink" {
					e = os.Symlink(c.Gateway, p)
				} else if kind == "fifo" {
					e = syscall.Mkfifo(p, 0600)
				} else {
					e = os.Link(c.Gateway, p)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e := Verify(context.Background(), c, path); e == nil {
				t.Fatal("unsafe bundle accepted", kind)
			}
		})
	}
}
func seedAuthorities(t *testing.T, s *store.Store) {
	t.Helper()
	statements := []string{
		"INSERT INTO owners VALUES('owner','fixture-password-hash','2026-10-15T00:00:00Z')",
		"INSERT INTO sessions VALUES('session-hash','owner','csrf',1,1,2147483647)",
		"INSERT INTO idempotency VALUES('prior-approval','digest','response')",
		"INSERT INTO connections(id,document,state) VALUES('connection','{}','active')",
		"INSERT INTO invites(id,connection,challenge_hash,expires) VALUES('invite','connection','challenge',2147483647)",
		"INSERT INTO consents(id,connection,incident,expires) VALUES('consent','connection','incident',2147483647)",
		"INSERT INTO handoffs(id,connection,incident,document,expires) VALUES('handoff','connection','incident','{}',2147483647)",
		"INSERT INTO drafts VALUES('draft','connection','incident','ready','{}','digest','key')",
		"INSERT INTO scope_grants VALUES('scope','owner','app_demo','{}','scope-digest','active',2147483647,0,'2026-10-15T00:00:00Z')",
		"INSERT INTO research_jobs(id,owner,app,kind,scope,input_digest,request_digest,idempotency_key,state,payload,created_at) VALUES('research','owner','app_demo','fixture','scope','input','request','research-key','running','{}','2026-10-15T00:00:00Z')",
		"INSERT INTO repositories VALUES('repo','owner','app_demo','fixture','map','2026-10-15T00:00:00Z')",
		"INSERT INTO application_maps VALUES('repo','map','{}','2026-10-15T00:00:00Z')",
		"INSERT INTO scanner_workers VALUES('worker','owner','worker-token-hash','active',2147483647,'2026-10-15T00:00:00Z')",
		"INSERT INTO scanner_verifiers VALUES('verifier','owner','verifier-token-hash','active','engine','registry',2147483647,'2026-10-15T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('scan','owner','repo','app_demo','map','lock','request','scan-key','{}','running','2026-10-15T00:00:00Z',2147483647)",
		"INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state) VALUES(1,'scan','worker','old-capability-hash',2147483647,2147483647,'active')",
	}
	for _, statement := range statements {
		if _, e := s.DB.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	p, d, _ := s.Active()
	p.Parent = d
	p.Metadata.Rationale = "Pending approval before snapshot"
	raw, _ := json.Marshal(p)
	if _, e := s.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", domain.Digest(p), d, string(raw), "PENDING_APPROVAL", domain.Now(), "owner"); e != nil {
		t.Fatal(e)
	}
	s.Set("preview:"+domain.Digest(p), "prior-proof")
}
func TestOfflineRestoreInvalidatesAuthorityPreservesHistoryAndCleanupHold(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	path, created := makeBundle(t, c, parent)
	original, e := os.ReadFile(filepath.Join(path, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(parent, "restored")
	result, e := Restore(context.Background(), c, path, destination, created.Bundle)
	if e != nil || !result.Authorities || !result.CleanupHeld || result.Activated || result.RestoreVerified || result.Signature {
		t.Fatal(result, e)
	}
	state, e := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer state.DB.Close()
	for _, table := range []string{"sessions", "idempotency", "invites", "consents", "handoffs"} {
		var n int
		if e = state.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("restored authority survived", table, n, e)
		}
	}
	for _, table := range []string{"scope_grants", "scanner_workers", "scanner_verifiers", "connections"} {
		var n int
		if e = state.DB.QueryRow("SELECT count(*) FROM " + table + " WHERE state='active'").Scan(&n); e != nil || n != 0 {
			t.Fatal("active restored role", table, n, e)
		}
	}
	var dispatch, job string
	if e = state.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&dispatch); e != nil || dispatch != "cleanup_required" {
		t.Fatal("cleanup hold released", dispatch, e)
	}
	if e = state.DB.QueryRow("SELECT state FROM scanner_jobs").Scan(&job); e != nil || job != "cancelled" {
		t.Fatal("job revived", job, e)
	}
	var pending int
	state.DB.QueryRow("SELECT count(*) FROM policies WHERE state='PENDING_APPROVAL'").Scan(&pending)
	if pending != 0 {
		t.Fatal("ghost approval")
	}
	if value, e := state.Get("history-marker"); e != nil || value != "private-retained-marker" {
		t.Fatal("history lost")
	}
	if state.VerifyAuditContext(context.Background()) != nil {
		t.Fatal("restore audit invalid")
	}
	after, _ := os.ReadFile(filepath.Join(path, "state.db"))
	if !bytes.Equal(original, after) {
		t.Fatal("bundle source changed")
	}
	if _, e = Restore(context.Background(), c, path, destination, created.Bundle); e == nil {
		t.Fatal("existing restore overwritten")
	}
	if _, e = Verify(context.Background(), c, path); e != nil {
		t.Fatal("original no longer verifies", e)
	}
}
func TestRestoreRequiresExactConfirmationAndRefusesBundleDescendant(t *testing.T) {
	c, _, parent := fixture(t)
	path, created := makeBundle(t, c, parent)
	wrong := filepath.Join(parent, "wrong")
	if _, e := Restore(context.Background(), c, path, wrong, "sha256:"+strings.Repeat("0", 64)); e == nil {
		t.Fatal("wrong confirmation accepted")
	}
	if _, e := os.Lstat(wrong); !os.IsNotExist(e) {
		t.Fatal("destination created before approval")
	}
	if _, e := Restore(context.Background(), c, path, filepath.Join(path, "child"), created.Bundle); e == nil {
		t.Fatal("bundle descendant used")
	}
}
func TestBundleNamespaceLockExcludesConcurrentReadersAndIncompleteState(t *testing.T) {
	c, _, parent := fixture(t)
	path, _ := makeBundle(t, c, parent)
	held, e := openPrivate(path, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(context.Background(), c, path); e == nil {
		t.Fatal("live writer lock ignored")
	}
	held.close()
	os.Remove(filepath.Join(path, "manifest.json"))
	if _, e = Verify(context.Background(), c, path); e == nil {
		t.Fatal("incomplete bundle accepted")
	}
}

func TestRestoreAuditFailureRollsBackAuthorityAndPublishesNoDestination(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	if _, e := s.DB.Exec(`CREATE TRIGGER reject_restore_audit BEFORE INSERT ON audit WHEN NEW.document LIKE '%recovery.authority_invalidated%' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); e != nil {
		t.Fatal(e)
	}
	path, created := makeBundle(t, c, parent)
	destination := filepath.Join(parent, "failed-restore")
	if _, e := Restore(context.Background(), c, path, destination, created.Bundle); e == nil {
		t.Fatal("unaudited restore succeeded")
	}
	if _, e := os.Lstat(destination); !os.IsNotExist(e) {
		t.Fatal("failed restore published")
	}
	var active int
	s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&active)
	if active != 1 {
		t.Fatal("source authority changed")
	}
	if _, e := Verify(context.Background(), c, path); e != nil {
		t.Fatal("source bundle changed", e)
	}
}
func TestIncompleteRestoredDataCannotStartOrBecomeSnapshotSource(t *testing.T) {
	_, s, parent := fixture(t)
	if e := os.WriteFile(filepath.Join(parent, store.RestorePending), []byte("recovery-v1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if reopened, e := store.Open(s.Path); e == nil {
		reopened.DB.Close()
		t.Fatal("incomplete state started")
	}
	if reopened, e := store.OpenSnapshotSource(context.Background(), s.Path); e == nil {
		reopened.DB.Close()
		t.Fatal("incomplete state snapshotted")
	}
}
