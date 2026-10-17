//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package recovery

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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
		"INSERT INTO scanner_authorizers VALUES('authorizer','owner','authorizer-token-hash','active','engine','registry','policy',2147483647,'2026-10-15T00:00:00Z')",
		"INSERT INTO connector_credentials(id,owner,name,token_hash,scope,state,created_at,expires) VALUES('connector','owner','Desktop assistant','connector-token-hash','read_defence_v1','active','2026-10-15T00:00:00Z',2147483647)",
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
	s.Set("scanner_engine_binding", "prior-host-authority")
	s.Set("scanner_engine_journal_binding", "prior-journal-authority")
	s.Set("scanner_engine_broker_binding", "prior-broker-authority")
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
	for _, table := range []string{"scope_grants", "scanner_workers", "scanner_verifiers", "scanner_authorizers", "connector_credentials", "connections"} {
		var n int
		if e = state.DB.QueryRow("SELECT count(*) FROM " + table + " WHERE state='active'").Scan(&n); e != nil || n != 0 {
			t.Fatal("active restored role", table, n, e)
		}
	}
	if _, e = state.Get("scanner_engine_binding"); e != sql.ErrNoRows {
		t.Fatal("restored engine authority survived", e)
	}
	if _, e = state.Get("scanner_engine_journal_binding"); e != sql.ErrNoRows {
		t.Fatal("restored journal authority survived", e)
	}
	if _, e = state.Get("scanner_engine_broker_binding"); e != sql.ErrNoRows {
		t.Fatal("restored broker authority survived", e)
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

func TestVersionThirteenBundleRestoresWithoutRequiringAuthorizerTable(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	// Construct the exact previously supported prefix in a disposable fixture.
	removeAllocationSchema(t, s)
	if _, e := s.DB.Exec("DROP TABLE scanner_authorizers"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DROP TABLE connector_credentials"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DELETE FROM migrations WHERE version>=14"); e != nil {
		t.Fatal(e)
	}
	path, created := makeBundle(t, c, parent)
	if _, e := Verify(context.Background(), c, path); e != nil {
		t.Fatal("legacy bundle refused", e)
	}
	destination := filepath.Join(parent, "restored-v13")
	if _, e := Restore(context.Background(), c, path, destination, created.Bundle); e != nil {
		t.Fatal("legacy restore failed", e)
	}
	state, e := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if e != nil {
		t.Fatal(e)
	}
	var version int
	if e = state.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&version); e != nil || version != 13 {
		t.Fatal("offline restore upgraded legacy bytes", e)
	}
	state.DB.Close()
	upgraded, e := store.Open(filepath.Join(destination, "data/aegis.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer upgraded.DB.Close()
	var n int
	if e = upgraded.DB.QueryRow("SELECT count(*) FROM scanner_authorizers").Scan(&n); e != nil || n != 0 {
		t.Fatal("legacy upgrade gained authorizer authority", e)
	}
	if e = upgraded.DB.QueryRow("SELECT count(*) FROM scanner_verifiers WHERE state='active'").Scan(&n); e != nil || n != 0 {
		t.Fatal("legacy observer authority survived", e)
	}
	var held string
	if e = upgraded.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&held); e != nil || held != "cleanup_required" {
		t.Fatal("legacy cleanup hold lost", e)
	}
}

func TestRecoveryRefusesAuthorizerTableOutsideDeclaredMigration(t *testing.T) {
	for _, kind := range []string{"undeclared-table", "missing-table"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			statement := "DELETE FROM migrations WHERE version=14"
			if kind == "missing-table" {
				statement = "DROP TABLE scanner_authorizers"
			}
			if _, e := s.DB.Exec(statement); e != nil {
				t.Fatal(e)
			}
			if _, e := Create(context.Background(), c, filepath.Join(parent, "refused-bundle")); e == nil {
				t.Fatal("mismatched authorizer schema accepted")
			}
		})
	}
}

// Remove migration016 only in a disposable legacy fixture. Keep the actual
// prefix and its original checksums, rather than teaching restore to upgrade.
func removeAllocationSchema(t *testing.T, s *store.Store) {
	t.Helper()
	removeReconcilerSchema(t, s)
	for _, statement := range []string{
		"DROP TRIGGER scanner_generation_job_closed", "DROP TRIGGER scanner_generation_dispatch_closed",
		"DROP TRIGGER scanner_generation_authorizer_revoked", "DROP TRIGGER scanner_generation_worker_revoked", "DROP TRIGGER scanner_generation_dispatch_held",
		"DROP TABLE scanner_mutation_intents", "DROP TABLE scanner_allocation_generations", "DROP TABLE scanner_mutation_bindings",
		"DELETE FROM migrations WHERE version=16",
	} {
		if _, e := s.DB.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
}

func removeReconcilerSchema(t *testing.T, s *store.Store) {
	t.Helper()
	for _, statement := range []string{"DROP TABLE scanner_cleanup_confirmations", "DELETE FROM migrations WHERE version=18", "DROP TABLE scanner_reconcilers", "DELETE FROM migrations WHERE version=17"} {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVersionSixteenRestoreClosesGenerationWithoutSettlingObligations(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	removeReconcilerSchema(t, s)
	for _, statement := range []string{
		"INSERT INTO scanner_mutation_bindings VALUES('binding','owner','authorizer','engine','registry','policy','namespace','broker','2026-10-15T00:00:00Z','active')",
		"INSERT INTO scanner_allocation_generations(job,id,owner,worker,binding_digest,lease_hash,deadline,guard_digest,created_at,state) VALUES('scan','generation','owner','worker','binding','old-capability-hash',2147483647,'guard','2026-10-15T00:00:00Z','open')",
		"INSERT INTO scanner_mutation_intents(id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,created_at,state) VALUES('intent','generation','scan','bandit','create','launch','workspace','container','descriptor','','2026-10-15T00:00:00Z','pending')",
	} {
		if _, e := s.DB.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	path, created := makeBundle(t, c, parent)
	destination := filepath.Join(parent, "restored-ledger")
	if _, e := Restore(context.Background(), c, path, destination, created.Bundle); e != nil {
		t.Fatal(e)
	}
	restored, e := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer restored.DB.Close()
	var state, descriptor, response string
	if e = restored.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE id='generation'").Scan(&state); e != nil || state != "closed" {
		t.Fatal("restore did not close admission", e)
	}
	if e = restored.DB.QueryRow("SELECT state FROM scanner_mutation_bindings WHERE digest='binding'").Scan(&state); e != nil || state != "revoked" {
		t.Fatal("restore kept selected authority", e)
	}
	if e = restored.DB.QueryRow("SELECT state,descriptor_digest,response_digest FROM scanner_mutation_intents WHERE id='intent'").Scan(&state, &descriptor, &response); e != nil || state != "pending" || descriptor != "descriptor" || response != "" {
		t.Fatal("restore changed unresolved mutation", e)
	}
	if e = restored.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job='scan'").Scan(&state); e != nil || state != "cleanup_required" {
		t.Fatal("restore freed dispatch", e)
	}
}

func TestLegacyFourteenAndFifteenRestoreWithoutAllocationTables(t *testing.T) {
	for _, version := range []int{14, 15} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			c, s, parent := fixture(t)
			seedAuthorities(t, s)
			removeAllocationSchema(t, s)
			if version == 14 {
				if _, e := s.DB.Exec("DROP TABLE connector_credentials; DELETE FROM migrations WHERE version=15"); e != nil {
					t.Fatal(e)
				}
			}
			path, created := makeBundle(t, c, parent)
			destination := filepath.Join(parent, "restored-prefix")
			if _, e := Restore(context.Background(), c, path, destination, created.Bundle); e != nil {
				t.Fatal(e)
			}
			restored, e := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
			if e != nil {
				t.Fatal(e)
			}
			defer restored.DB.Close()
			var actual, n int
			if e = restored.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&actual); e != nil || actual != version {
				t.Fatal("restore upgraded prefix", e)
			}
			if e = restored.DB.QueryRow("SELECT count(*) FROM scanner_authorizers WHERE state='active'").Scan(&n); e != nil || n != 0 {
				t.Fatal("legacy authorizer survived", e)
			}
		})
	}
}
