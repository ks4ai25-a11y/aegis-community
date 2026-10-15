// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package store

import (
	"aegis.local/controller/internal/domain"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func backupFixture(t *testing.T) (*Store, string) {
	t.Helper()
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(filepath.Join(parent, "source.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if e = s.Set("backup-private-canary", "must remain local"); e != nil {
		t.Fatal(e)
	}
	return s, parent
}
func assertNoBackupStages(t *testing.T, parent string) {
	t.Helper()
	entries, e := os.ReadDir(parent)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".aegis-backup-") {
			t.Fatal("partial staging artifact retained after handled failure")
		}
	}
}
func TestBackupPublishesPrivateSnapshotAndNeverOverwrites(t *testing.T) {
	s, parent := backupFixture(t)
	path := filepath.Join(parent, "snapshot.db")
	if e := s.Backup(context.Background(), path); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(path)
	if e != nil || !backupFile(info) {
		t.Fatal("snapshot not private", e)
	}
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Set("backup-private-canary", "newer live value"); e != nil {
		t.Fatal(e)
	}
	if e = s.Backup(context.Background(), path); !errors.Is(e, ErrBackup) {
		t.Fatal("existing output replaced", e)
	}
	unchanged, e := os.ReadFile(path)
	if e != nil || string(unchanged) != string(original) {
		t.Fatal("snapshot contents changed")
	}
	copied, e := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if e != nil {
		t.Fatal(e)
	}
	defer copied.Close()
	var value string
	if e = copied.QueryRow("SELECT value FROM settings WHERE key='backup-private-canary'").Scan(&value); e != nil || value != "must remain local" {
		t.Fatal("snapshot did not preserve committed state", e)
	}
	var integrity string
	if e = copied.QueryRow("PRAGMA quick_check").Scan(&integrity); e != nil || integrity != "ok" {
		t.Fatal("snapshot integrity", e)
	}
	assertNoBackupStages(t, parent)
}
func TestBackupRefusesSymlinkFifoExistingAndUnsafeParent(t *testing.T) {
	for _, kind := range []string{"symlink", "dangling_symlink", "fifo", "empty_existing", "writable_parent", "relative", "unclean"} {
		t.Run(kind, func(t *testing.T) {
			s, parent := backupFixture(t)
			path := filepath.Join(parent, "snapshot.db")
			target := filepath.Join(parent, "must-not-change")
			os.WriteFile(target, []byte("private sentinel"), 0600)
			switch kind {
			case "symlink":
				if e := os.Symlink(target, path); e != nil {
					t.Fatal(e)
				}
			case "dangling_symlink":
				if e := os.Symlink(filepath.Join(parent, "never-created"), path); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "empty_existing":
				os.WriteFile(path, nil, 0600)
			case "writable_parent":
				os.Chmod(parent, 0777)
				defer os.Chmod(parent, 0700)
			case "relative":
				path = "relative-backup-must-not-appear.db"
			case "unclean":
				path = parent + "/../" + filepath.Base(parent) + "/snapshot.db"
			}
			if e := s.Backup(context.Background(), path); !errors.Is(e, ErrBackup) {
				t.Fatal("unsafe output accepted", e)
			}
			b, e := os.ReadFile(target)
			if e != nil || string(b) != "private sentinel" {
				t.Fatal("unrelated target changed")
			}
			if _, e = os.Lstat(filepath.Join(parent, "never-created")); !os.IsNotExist(e) {
				t.Fatal("dangling target created")
			}
			assertNoBackupStages(t, parent)
		})
	}
}
func TestBackupCancellationBeforeAndDuringConnectionWaitPublishesNothing(t *testing.T) {
	s, parent := backupFixture(t)
	held, e := s.DB.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	for _, duration := range []time.Duration{0, 40 * time.Millisecond} {
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		path := filepath.Join(parent, "cancelled.db")
		started := time.Now()
		e = s.Backup(ctx, path)
		cancel()
		if !errors.Is(e, ErrBackup) || time.Since(started) > time.Second {
			t.Fatal("cancellation failed", e)
		}
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("cancelled snapshot published")
		}
		assertNoBackupStages(t, parent)
	}
}
func TestBackupConcurrentWriterKeepsCommittedTransactionCoherent(t *testing.T) {
	s, parent := backupFixture(t)
	if _, e := s.DB.Exec("CREATE TABLE backup_pair(a INTEGER NOT NULL,b INTEGER NOT NULL); INSERT INTO backup_pair VALUES(0,0)"); e != nil {
		t.Fatal(e)
	}
	// A second connection models the running controller while this local
	// operator owns its backup connection; both use the same WAL database.
	writer, e := sql.Open("sqlite", s.Path)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	if _, e = writer.Exec("PRAGMA busy_timeout=1000"); e != nil {
		t.Fatal(e)
	}
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		for i := 1; i <= 200; i++ {
			if _, e := writer.Exec("UPDATE backup_pair SET a=?,b=?", i, i); e != nil {
				done <- e
				return
			}
			if i == 1 {
				close(started)
			}
		}
		done <- nil
	}()
	select {
	case <-started:
	case e := <-done:
		t.Fatal("writer stopped before first transaction", e)
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not start")
	}
	path := filepath.Join(parent, "concurrent.db")
	if e = s.Backup(context.Background(), path); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	copy, e := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if e != nil {
		t.Fatal(e)
	}
	defer copy.Close()
	var a, b int
	if e = copy.QueryRow("SELECT a,b FROM backup_pair").Scan(&a, &b); e != nil || a != b || a < 1 || a > 200 {
		t.Fatal("torn transaction", a, b, e)
	}
	assertNoBackupStages(t, parent)
}
func TestBackupStorageWriteFailureDoesNotPublishPartialDatabase(t *testing.T) {
	if os.Getenv("AEGIS_BACKUP_WRITE_FAULT_HELPER") == "1" {
		s, e := Open(os.Getenv("AEGIS_BACKUP_SOURCE"))
		if e != nil {
			os.Exit(10)
		}
		signal.Ignore(syscall.SIGXFSZ)
		if e = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 32768, Max: 32768}); e != nil {
			os.Exit(11)
		}
		e = s.Backup(context.Background(), os.Getenv("AEGIS_BACKUP_DESTINATION"))
		s.DB.Close()
		if !errors.Is(e, ErrBackup) {
			os.Exit(12)
		}
		os.Exit(0)
	}
	s, parent := backupFixture(t)
	if _, e := s.DB.Exec("CREATE TABLE backup_blob(bytes BLOB); INSERT INTO backup_blob VALUES(zeroblob(1048576))"); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(parent, "must-not-publish.db")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBackupStorageWriteFailureDoesNotPublishPartialDatabase$")
	child.Env = append(os.Environ(), "AEGIS_BACKUP_WRITE_FAULT_HELPER=1", "AEGIS_BACKUP_SOURCE="+s.Path, "AEGIS_BACKUP_DESTINATION="+output)
	if e := child.Run(); e != nil {
		t.Fatal("write-fault subprocess failed", e)
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		t.Fatal("failed write published snapshot")
	}
	assertNoBackupStages(t, parent)
	var integrity string
	if e := s.DB.QueryRow("PRAGMA quick_check").Scan(&integrity); e != nil || integrity != "ok" {
		t.Fatal("source changed after backup failure", e)
	}
}

func TestBackupDoesNotResurrectDeletedPrivateContentFromFreePages(t *testing.T) {
	s, parent := backupFixture(t)
	marker := "deleted-private-backup-canary-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if _, e := s.DB.Exec("PRAGMA secure_delete=OFF; CREATE TABLE retired_private(value TEXT)"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("INSERT INTO retired_private VALUES(?)", strings.Repeat(marker, 1024)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DELETE FROM retired_private; PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(s.Path)
	if e != nil || !bytes.Contains(raw, []byte(marker)) {
		t.Fatal("fixture did not retain a deleted canary")
	}
	output := filepath.Join(parent, "without-deleted-content.db")
	if e = s.Backup(context.Background(), output); e != nil {
		t.Fatal(e)
	}
	snapshot, e := os.ReadFile(output)
	if e != nil || bytes.Contains(snapshot, []byte(marker)) {
		t.Fatal("snapshot resurrected deleted private content")
	}
	assertNoBackupStages(t, parent)
}

func TestBackupIntermediateBytesArePrivateAndLateExistingTargetWins(t *testing.T) {
	s, parent := backupFixture(t)
	held, e := s.DB.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	path := filepath.Join(parent, "concurrent-target.db")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- s.Backup(ctx, path) }()
	var stage string
	deadline := time.Now().Add(2 * time.Second)
	for stage == "" && time.Now().Before(deadline) {
		entries, e := os.ReadDir(parent)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".aegis-backup-") {
				stage = filepath.Join(parent, entry.Name())
				break
			}
		}
		if stage == "" {
			time.Sleep(time.Millisecond)
		}
	}
	if stage == "" {
		t.Fatal("backup did not allocate private staging")
	}
	info, e := os.Lstat(stage)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("staging directory is not private", e)
	}
	var bytesInfo os.FileInfo
	for time.Now().Before(deadline) {
		bytesInfo, e = os.Lstat(filepath.Join(stage, "state.db"))
		if e == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e != nil || !backupFile(bytesInfo) || bytesInfo.Size() != 0 {
		t.Fatal("staging file was not private before SQLite wrote", e)
	}
	sentinel := []byte("concurrent writer owns this target")
	if e = os.WriteFile(path, sentinel, 0600); e != nil {
		t.Fatal(e)
	}
	held.Close()
	if e = <-finished; !errors.Is(e, ErrBackup) {
		t.Fatal("concurrent target was replaced", e)
	}
	actual, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(actual, sentinel) {
		t.Fatal("concurrent target changed")
	}
	assertNoBackupStages(t, parent)
}

func TestBackupReceiptMatchesPrivateArtifactAndRetainsRecoveryUncertainty(t *testing.T) {
	s, parent := backupFixture(t)
	output := filepath.Join(parent, "receipt.db")
	receipt, e := s.BackupSnapshot(context.Background(), output)
	if e != nil {
		t.Fatal(e)
	}
	artifact, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	if receipt.Schema != "1.0" || receipt.Status != "created" || receipt.Scope != "controller_database_only" || receipt.Bytes != int64(len(artifact)) || receipt.Digest != domain.Hash(artifact) || receipt.Gateway || receipt.Tools || receipt.Restored {
		t.Fatal("receipt changed artifact scope", receipt)
	}
	if _, e = time.Parse(time.RFC3339Nano, receipt.Created); e != nil {
		t.Fatal(e)
	}
	encoded, e := json.Marshal(receipt)
	if e != nil || bytes.Contains(encoded, []byte(parent)) || bytes.Contains(encoded, []byte("must remain local")) {
		t.Fatal("receipt exposed private state")
	}
}
func TestBackupURICharactersInOwnedOutputDirectoryRemainLiteral(t *testing.T) {
	s, parent := backupFixture(t)
	parent = filepath.Join(parent, "private ?# export")
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(parent, "snapshot?#.db")
	if e := s.Backup(context.Background(), output); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(output)
	if e != nil || !backupFile(info) {
		t.Fatal("URI characters changed output identity", e)
	}
	assertNoBackupStages(t, parent)
}

func TestSnapshotSourceMissingOrUninitializedStateNeverCreatesDatabase(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	missing := filepath.Join(parent, "missing", "aegis.db")
	if source, e := OpenSnapshotSource(context.Background(), missing); e == nil {
		source.DB.Close()
		t.Fatal("missing state initialized")
	}
	if _, e := os.Lstat(filepath.Dir(missing)); !os.IsNotExist(e) {
		t.Fatal("source directory created")
	}
	empty := filepath.Join(parent, "empty.db")
	os.WriteFile(empty, nil, 0600)
	if source, e := OpenSnapshotSource(context.Background(), empty); e == nil {
		source.DB.Close()
		t.Fatal("empty state initialized")
	}
	stat, _ := os.Stat(empty)
	if stat.Size() != 0 {
		t.Fatal("empty source changed")
	}
}
func TestSnapshotSourceReadOnlyAndDoesNotUpgradeOlderMigrationPrefix(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(parent, "legacy.db")
	database, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = database.Exec(schema); e != nil {
		t.Fatal(e)
	}
	if _, e = database.Exec("INSERT INTO migrations VALUES(1,?); INSERT INTO settings VALUES('legacy-canary','preserved')", domain.Hash([]byte(schema))); e != nil {
		t.Fatal(e)
	}
	database.Close()
	os.Chmod(path, 0600)
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	source, e := OpenSnapshotSource(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer source.DB.Close()
	if e = source.Set("unexpected-write", "refused"); e == nil {
		t.Fatal("snapshot source writable")
	}
	output := filepath.Join(parent, "legacy-snapshot.db")
	if _, e = source.BackupSnapshot(context.Background(), output); e != nil {
		t.Fatal(e)
	}
	snapshot, e := sql.Open("sqlite", "file:"+output+"?mode=ro&immutable=1")
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	var version int
	var marker string
	if e = snapshot.QueryRow("SELECT max(version) FROM migrations").Scan(&version); e != nil || version != 1 {
		t.Fatal("snapshot source was upgraded", version, e)
	}
	if e = snapshot.QueryRow("SELECT value FROM settings WHERE key='legacy-canary'").Scan(&marker); e != nil || marker != "preserved" {
		t.Fatal("legacy state lost", e)
	}
	source.DB.Close()
	final, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(original, final) {
		t.Fatal("read-only source bytes changed")
	}
}
func TestSnapshotSourceRefusesUnknownOrChangedMigrationHistory(t *testing.T) {
	for _, kind := range []string{"future", "checksum", "gap", "no_versions", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			s, parent := backupFixture(t)
			path := s.Path
			switch kind {
			case "future":
				s.DB.Exec("INSERT INTO migrations VALUES(99,'unknown')")
			case "checksum":
				s.DB.Exec("UPDATE migrations SET checksum='changed' WHERE version=1")
			case "gap":
				s.DB.Exec("DELETE FROM migrations WHERE version=2")
			case "no_versions":
				s.DB.Exec("DELETE FROM migrations")
			case "symlink":
				path = filepath.Join(parent, "alias.db")
				if e := os.Symlink(s.Path, path); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				path = filepath.Join(parent, "fifo.db")
				if e := syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if source, e := OpenSnapshotSource(context.Background(), path); e == nil {
				source.DB.Close()
				t.Fatal("unsupported source accepted", kind)
			}
		})
	}
}

func TestBackupRejectsUnsupportedHistoryIntroducedAfterSourcePreflight(t *testing.T) {
	writer, parent := backupFixture(t)
	source, e := OpenSnapshotSource(context.Background(), writer.Path)
	if e != nil {
		t.Fatal(e)
	}
	defer source.DB.Close()
	if _, e = writer.DB.Exec("INSERT INTO migrations VALUES(99,'concurrent-future-version')"); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(parent, "must-not-publish-future.db")
	if _, e = source.BackupSnapshot(context.Background(), output); !errors.Is(e, ErrBackup) {
		t.Fatal("future snapshot published", e)
	}
	if _, e = os.Lstat(output); !os.IsNotExist(e) {
		t.Fatal("unsupported artifact reached final name")
	}
	var latest int
	if e = writer.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&latest); e != nil || latest != 99 {
		t.Fatal("source history was changed", e)
	}
	assertNoBackupStages(t, parent)
}
