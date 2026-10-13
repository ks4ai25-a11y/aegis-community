package store

import (
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
