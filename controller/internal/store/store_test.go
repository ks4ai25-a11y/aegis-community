package store

import (
	"aegis.local/controller/internal/domain"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestAuditTamperDetected(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if e = s.Audit("owner", "test", "object", "ok", nil); e != nil {
		t.Fatal(e)
	}
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	s.DB.Exec("UPDATE audit SET document='{}' WHERE seq=1")
	if s.VerifyAudit() == nil {
		t.Fatal("tampering accepted")
	}
}
func TestConsistentBackup(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(filepath.Join(dir, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	s.Set("canary", "retained")
	backup := filepath.Join(dir, "backup.db")
	if e = s.Backup(context.Background(), backup); e != nil {
		t.Fatal(e)
	}
	b, e := Open(backup)
	if e != nil {
		t.Fatal(e)
	}
	defer b.DB.Close()
	if v, e := b.Get("canary"); e != nil || v != "retained" {
		t.Fatal(v, e)
	}
}

func TestUnknownMigrationDoesNotTouchSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO migrations VALUES(99,'future')"); e != nil {
		t.Fatal(e)
	}
	var originalCount int
	if e = s.DB.QueryRow("SELECT count(*) FROM migrations").Scan(&originalCount); e != nil {
		t.Fatal(e)
	}
	s.DB.Close()
	if _, e = Open(path); e == nil {
		t.Fatal("future version accepted")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var n int
	if e = db.QueryRow("SELECT count(*) FROM migrations").Scan(&n); e != nil || n != originalCount {
		t.Fatal("migration history changed", n, e)
	}
}

func TestScannerMigrationUpgradePreservesExistingVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	for i, body := range []string{schema, researchSchema, repositorySchema} {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.Exec("INSERT INTO settings VALUES('upgrade-canary','preserved')"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range []string{schema, researchSchema, repositorySchema} {
		var hash string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&hash); e != nil || hash != domain.Hash([]byte(body)) {
			t.Fatal("old migration changed", i, e)
		}
	}
	var version int
	if e = s.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&version); e != nil || version != len(migrationBodies()) {
		t.Fatal(version, e)
	}
	if got, e := s.Get("upgrade-canary"); e != nil || got != "preserved" {
		t.Fatal(got, e)
	}
	if _, e = s.DB.Exec("SELECT count(*) FROM scanner_jobs"); e != nil {
		t.Fatal(e)
	}
}

func TestScannerLeaseMigrationPreservesVersionFourJobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	previous := []string{schema, researchSchema, repositorySchema, scannerSchema}
	for i, body := range previous {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('upgrade-owner','fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO repositories VALUES('upgrade-repo','upgrade-owner','app_demo','fixture','map-fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO application_maps VALUES('upgrade-repo','map-fixture','{}','2026-10-13T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('upgrade-job','upgrade-owner','upgrade-repo','app_demo','map-fixture','lock-fixture','request-fixture','upgrade-key','{}','queued','2026-10-13T00:00:00Z',1791849600)",
	} {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range previous {
		var hash string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&hash); e != nil || hash != domain.Hash([]byte(body)) {
			t.Fatal("previous checksum changed", i, e)
		}
	}
	var state, digest string
	if e = s.DB.QueryRow("SELECT state,request_digest FROM scanner_jobs WHERE id='upgrade-job'").Scan(&state, &digest); e != nil || state != "queued" || digest != "request-fixture" {
		t.Fatal("old request altered", state, digest, e)
	}
	var n int
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n); e != nil || n != 0 {
		t.Fatal("migration fabricated a worker claim", n, e)
	}
}

func TestWorkerRoleMigrationPreservesDispatchWithoutImplicitEnrollment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v5-worker.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	previous := []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema}
	for i, body := range previous {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('worker-upgrade-owner','fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO repositories VALUES('worker-upgrade-repo','worker-upgrade-owner','app_demo','fixture','map-fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO application_maps VALUES('worker-upgrade-repo','map-fixture','{}','2026-10-13T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('worker-upgrade-job','worker-upgrade-owner','worker-upgrade-repo','app_demo','map-fixture','lock-fixture','request-fixture','upgrade-key','{}','running','2026-10-13T00:00:00Z',1791849600)",
		"INSERT INTO scanner_dispatch VALUES(1,'worker-upgrade-job','prior-worker','capability-hash-fixture',1791849600,1791849600,'cleanup_required')",
	} {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range previous {
		var hash string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&hash); e != nil || hash != domain.Hash([]byte(body)) {
			t.Fatal("prior migration checksum changed", i, e)
		}
	}
	var n int
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_workers").Scan(&n); e != nil || n != 0 {
		t.Fatal("migration invented worker authority", n, e)
	}
	var state, hash string
	if e = s.DB.QueryRow("SELECT state,token_hash FROM scanner_dispatch WHERE slot=1").Scan(&state, &hash); e != nil || state != "cleanup_required" || hash != "capability-hash-fixture" {
		t.Fatal("migration changed uncertain admission", state, e)
	}
	var protocol int
	if e = s.DB.QueryRow("SELECT launch_protocol FROM scanner_dispatch WHERE slot=1").Scan(&protocol); e != nil || protocol != 0 {
		t.Fatal("migration invented journaled launch authority", protocol, e)
	}
	if e = s.DB.QueryRow("SELECT workspace_protocol FROM scanner_dispatch WHERE slot=1").Scan(&protocol); e != nil || protocol != 0 {
		t.Fatal("migration invented workspace authority", protocol, e)
	}
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n); e != nil || n != 0 {
		t.Fatal("migration invented workspace records", n, e)
	}
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n); e != nil || n != 0 {
		t.Fatal("migration invented launch evidence", n, e)
	}
}

func TestReceiptMigrationPreservesVersionSixWorkerAndPriorState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6-receipts.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	previous := []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema}
	for i, body := range previous {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('receipt-owner','fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO scanner_workers VALUES('receipt-worker','receipt-owner','fixture-capability-hash','active',1791849600,'2026-10-13T00:00:00Z')",
		"INSERT INTO settings VALUES('receipt-upgrade-canary','preserved')",
	} {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range previous {
		var hash string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&hash); e != nil || hash != domain.Hash([]byte(body)) {
			t.Fatal("deployed migration checksum changed")
		}
	}
	var hash, state string
	if e = s.DB.QueryRow("SELECT token_hash,state FROM scanner_workers WHERE id='receipt-worker'").Scan(&hash, &state); e != nil || hash != "fixture-capability-hash" || state != "active" {
		t.Fatal("receipt migration altered enrollment")
	}
	var n int
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n); e != nil || n != 0 {
		t.Fatal("migration invented evidence")
	}
	if value, e := s.Get("receipt-upgrade-canary"); e != nil || value != "preserved" {
		t.Fatal("upgrade lost prior state")
	}
}

func TestWorkspaceMigrationQuarantinesVersionNineDispatchWithoutInventingReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v9-workspaces.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	prior := []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema, scannerReceiptSchema, scannerResultSchema, scannerLaunchSchema}
	for i, body := range prior {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('v9-owner','fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO repositories VALUES('v9-repo','v9-owner','app_demo','fixture','map','2026-10-13T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('v9-job','v9-owner','v9-repo','app_demo','map','lock','request','key','{}','running','2026-10-13T00:00:00Z',1791849600)",
		"INSERT INTO scanner_dispatch VALUES(1,'v9-job','original-worker','original-capability-hash',1791849600,1791849600,'active',1)",
		"INSERT INTO scanner_launches VALUES('v9-job','bandit','v9-owner','request','original-container','original-workspace','original-digest','{}','2026-10-13T00:00:00Z')",
	} {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	var launch, workspace int
	var state, hash string
	if e = s.DB.QueryRow("SELECT state,token_hash,launch_protocol,workspace_protocol FROM scanner_dispatch").Scan(&state, &hash, &launch, &workspace); e != nil || state != "active" || hash != "original-capability-hash" || launch != 1 || workspace != 0 {
		t.Fatal("upgrade changed or revived old authority", e)
	}
	var n int
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n); e != nil || n != 0 {
		t.Fatal("upgrade invented reservations", e)
	}
	var digest string
	if e = s.DB.QueryRow("SELECT digest FROM scanner_launches").Scan(&digest); e != nil || digest != "original-digest" {
		t.Fatal("upgrade rewrote old evidence", e)
	}
	for i, body := range prior {
		var checksum string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&checksum); e != nil || checksum != domain.Hash([]byte(body)) {
			t.Fatal("prior checksum changed", e)
		}
	}
}

func TestGuardMigrationPreservesVersionTenDispatchWithoutInventingBuildAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v10-guards.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	prior := []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema, scannerReceiptSchema, scannerResultSchema, scannerLaunchSchema, scannerWorkspaceSchema}
	for i, body := range prior {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('v10-owner','fixture','2026-10-13T00:00:00Z')",
		"INSERT INTO repositories VALUES('v10-repo','v10-owner','app_demo','fixture','map','2026-10-13T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('v10-job','v10-owner','v10-repo','app_demo','map','lock','request','key','{}','running','2026-10-13T00:00:00Z',1791849600)",
		"INSERT INTO scanner_dispatch VALUES(1,'v10-job','original-worker','original-capability-hash',1791849600,1791849600,'active',1,1)",
		"INSERT INTO scanner_launches VALUES('v10-job','bandit','v10-owner','request','original-container','original-workspace','original-digest','{}','2026-10-13T00:00:00Z')",
	} {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	var state, token, guard string
	if e = s.DB.QueryRow("SELECT state,token_hash,guard_set_digest FROM scanner_dispatch").Scan(&state, &token, &guard); e != nil || state != "active" || token != "original-capability-hash" || guard != "" {
		t.Fatal("upgrade invented guard authority", e)
	}
	var d string
	if e = s.DB.QueryRow("SELECT digest FROM scanner_launches").Scan(&d); e != nil || d != "original-digest" {
		t.Fatal("upgrade rewrote historical evidence", e)
	}
	for i, body := range prior {
		var checksum string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&checksum); e != nil || checksum != domain.Hash([]byte(body)) {
			t.Fatal("migration checksum changed", e)
		}
	}
}

func TestFindingTriageMigrationPreservesVersionElevenState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v11.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	previous := []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema, scannerReceiptSchema, scannerResultSchema, scannerLaunchSchema, scannerWorkspaceSchema, scannerGuardSchema}
	for i, body := range previous {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.Exec("INSERT INTO settings VALUES('triage-upgrade-canary','preserved')"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range previous {
		var hash string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&hash); e != nil || hash != domain.Hash([]byte(body)) {
			t.Fatal("prior migration changed", i, e)
		}
	}
	var version, n int
	if e = s.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&version); e != nil || version != len(migrationBodies()) {
		t.Fatal(version, e)
	}
	if e = s.DB.QueryRow("SELECT count(*) FROM finding_triage").Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if value, e := s.Get("triage-upgrade-canary"); e != nil || value != "preserved" {
		t.Fatal(value, e)
	}
}

func TestScannerVerifierMigrationPreservesVersionTwelveState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v12.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	previous := []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema, scannerReceiptSchema, scannerResultSchema, scannerLaunchSchema, scannerWorkspaceSchema, scannerGuardSchema, findingTriageSchema}
	for i, body := range previous {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = db.Exec("INSERT INTO owners VALUES('retained-owner','test','2026-10-14T00:00:00Z')"); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO settings VALUES('verifier-upgrade-canary','preserved')"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range previous {
		var hash string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&hash); e != nil || hash != domain.Hash([]byte(body)) {
			t.Fatal("prior migration changed", i, e)
		}
	}
	var n int
	if e = s.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&n); e != nil || n != len(migrationBodies()) {
		t.Fatal(n, e)
	}
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_verifiers").Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if e = s.DB.QueryRow("SELECT count(*) FROM owners WHERE id='retained-owner'").Scan(&n); e != nil || n != 1 {
		t.Fatal("owner state lost", e)
	}
	if value, e := s.Get("verifier-upgrade-canary"); e != nil || value != "preserved" {
		t.Fatal(value, e)
	}
}

func TestAuthorizerMigrationPreservesVersionThirteenEnrollmentsAndHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v13.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	previous := migrationBodies()[:13]
	for i, body := range previous {
		if _, e = db.Exec(body); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("INSERT INTO migrations VALUES(?,?)", i+1, domain.Hash([]byte(body))); e != nil {
			t.Fatal(e)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('retained-owner','test','2026-10-16T00:00:00Z')",
		"INSERT INTO scanner_verifiers VALUES('retained-observer','retained-owner','observer-hash','active','engine','registry',2147483647,'2026-10-16T00:00:00Z')",
		"INSERT INTO repositories VALUES('repo','retained-owner','app_demo','fixture','map','2026-10-16T00:00:00Z')",
		"INSERT INTO application_maps VALUES('repo','map','{}','2026-10-16T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('retained-job','retained-owner','repo','app_demo','map','lock','request','key','{}','tool_error','2026-10-16T00:00:00Z',2147483647)",
		"INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state) VALUES(1,'retained-job','worker','token',1,2,'cleanup_required')",
	} {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for i, body := range previous {
		var checksum string
		if e = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", i+1).Scan(&checksum); e != nil || checksum != domain.Hash([]byte(body)) {
			t.Fatal("prior migration changed", i, e)
		}
	}
	var state string
	if e = s.DB.QueryRow("SELECT state FROM scanner_verifiers WHERE id='retained-observer'").Scan(&state); e != nil || state != "active" {
		t.Fatal("observer scope changed", e)
	}
	if e = s.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state); e != nil || state != "cleanup_required" {
		t.Fatal("hold changed", e)
	}
	var count int
	if e = s.DB.QueryRow("SELECT count(*) FROM scanner_authorizers").Scan(&count); e != nil || count != 0 {
		t.Fatal("migration created authorizer authority", e)
	}
}

func TestConnectorCredentialScopeImmutableAndRevocationOneWay(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "c.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	if _, e = s.DB.Exec("INSERT INTO owners VALUES('o','x','now')"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO connector_credentials(id,owner,name,token_hash,scope,state,created_at,expires) VALUES('c','o','Claude','h','read_defence_v1','active','now',9)"); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"UPDATE connector_credentials SET scope='admin'", "UPDATE connector_credentials SET expires=99999999999", "UPDATE connector_credentials SET token_hash='other'"} {
		if _, e = s.DB.Exec(bad); e == nil {
			t.Fatal("mutable", bad)
		}
	}
	if _, e = s.DB.Exec("INSERT INTO connector_credentials(id,owner,name,token_hash,scope,state,created_at,expires) VALUES('d','o','x','h2','write_everything','active','now',9)"); e == nil {
		t.Fatal("unknown scope accepted")
	}
	if _, e = s.DB.Exec("UPDATE connector_credentials SET state='revoked'"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("UPDATE connector_credentials SET state='active'"); e == nil {
		t.Fatal("revoked credential reactivated")
	}
}
