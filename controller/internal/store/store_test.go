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
	if e = s.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&version); e != nil || version != 8 {
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
