// SPDX-License-Identifier: Apache-2.0
package store

import (
	"aegis.local/controller/internal/domain"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
)

var ErrBackup = errors.New("private SQLite backup refused or incomplete")

const maxBackupBytes int64 = 512 << 20

// OpenSnapshotSource never creates or migrates source state. Recognized older
// migration prefixes can be captured before an upgrade changes their bytes.
func OpenSnapshotSource(ctx context.Context, path string) (*Store, error) {
	if refusePendingRestore(path) != nil {
		return nil, ErrBackup
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, ErrBackup
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(absolute))
	if e != nil {
		return nil, ErrBackup
	}
	info, e := os.Lstat(parent)
	if e != nil || !backupParent(info) {
		return nil, ErrBackup
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return nil, ErrBackup
	}
	defer root.Close()
	currentParent, e := root.Stat(".")
	if e != nil || !os.SameFile(info, currentParent) || !backupParent(currentParent) {
		return nil, ErrBackup
	}
	name := filepath.Base(absolute)
	before, e := root.Lstat(name)
	if e != nil || !backupFile(before) || before.Size() < 100 {
		return nil, ErrBackup
	}
	file, e := openBackupForRead(root, name)
	if e != nil {
		return nil, ErrBackup
	}
	defer file.Close()
	opened, e := file.Stat()
	if e != nil || !backupFile(opened) || !os.SameFile(before, opened) {
		return nil, ErrBackup
	}
	canonical := filepath.Join(parent, name)
	query := url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "busy_timeout(5000)"}}
	uri := (&url.URL{Scheme: "file", Path: canonical, RawQuery: query.Encode()}).String()
	db, e := sql.Open("sqlite", uri)
	if e != nil {
		return nil, ErrBackup
	}
	db.SetMaxOpenConns(1)
	valid := false
	defer func() {
		if !valid {
			db.Close()
		}
	}()
	if e = validateSnapshotHistory(ctx, db); e != nil {
		return nil, ErrBackup
	}
	after, e := root.Lstat(name)
	if e != nil || !backupFile(after) || !os.SameFile(before, after) {
		return nil, ErrBackup
	}
	valid = true
	return &Store{DB: db, Path: canonical}, nil
}

func validateSnapshotHistory(ctx context.Context, db *sql.DB) error {
	rows, e := db.QueryContext(ctx, "SELECT version,checksum FROM migrations ORDER BY version LIMIT 14")
	if e != nil {
		return ErrBackup
	}
	defer rows.Close()
	versions := migrationBodies()
	count := 0
	for rows.Next() {
		var version int
		var checksum string
		if e = rows.Scan(&version, &checksum); e != nil || count >= len(versions) || version != count+1 || checksum != domain.Hash([]byte(versions[count])) {
			return ErrBackup
		}
		count++
	}
	if rows.Err() != nil || count == 0 {
		return ErrBackup
	}
	return nil
}

// Backup publishes a private, exclusive snapshot only after SQLite's online
// backup API has completed and the snapshot file has been synced. It never
// copies a live database/WAL with ordinary file reads or overwrites a target.
func (s *Store) Backup(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrBackup
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return ErrBackup
	}
	before, e := os.Lstat(parent)
	if e != nil || !backupParent(before) {
		return ErrBackup
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return ErrBackup
	}
	defer root.Close()
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) || !backupParent(after) {
		return ErrBackup
	}
	name := filepath.Base(path)
	if _, e = root.Lstat(name); !os.IsNotExist(e) {
		return ErrBackup
	}
	stage, e := os.MkdirTemp(parent, ".aegis-backup-")
	if e != nil {
		return ErrBackup
	}
	defer os.RemoveAll(stage)
	staged := filepath.Join(stage, "state.db")
	file, e := os.OpenFile(staged, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrBackup
	}
	defer file.Close()
	inode, e := file.Stat()
	if e != nil || !backupFile(inode) {
		return ErrBackup
	}
	if e = s.copyOnline(ctx, staged, file); e != nil {
		return e
	}
	if e = compactPrivateSnapshot(ctx, staged); e != nil {
		return ErrBackup
	}
	current, e := os.Lstat(staged)
	if e != nil || !os.SameFile(inode, current) || !backupFile(current) || current.Size() < 100 || current.Size() > maxBackupBytes || ctx.Err() != nil {
		return ErrBackup
	}
	if e = file.Sync(); e != nil {
		return ErrBackup
	}
	// Link creates the final name atomically and refuses every existing file,
	// including a symlink or FIFO. All intermediate bytes stayed inside 0700.
	parentNow, e := os.Lstat(parent)
	if e != nil || !os.SameFile(before, parentNow) || !backupParent(parentNow) {
		return ErrBackup
	}
	if e = root.Link(filepath.Base(stage)+"/state.db", name); e != nil {
		return ErrBackup
	}
	if e = os.RemoveAll(stage); e != nil {
		return ErrBackup
	}
	published, e := root.Lstat(name)
	if e != nil || !os.SameFile(inode, published) || !backupFile(published) {
		return ErrBackup
	}
	directory, e := root.Open(".")
	if e != nil {
		return ErrBackup
	}
	defer directory.Close()
	if e = directory.Sync(); e != nil {
		return ErrBackup
	}
	return nil
}

// A page-for-page backup can retain deleted private values in freelist pages.
// Compact only the isolated destination, preserving the source and its WAL.
func compactPrivateSnapshot(ctx context.Context, path string) error {
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}).String()
	db, e := sql.Open("sqlite", uri)
	if e != nil {
		return ErrBackup
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if e = validateSnapshotHistory(ctx, db); e != nil {
		return ErrBackup
	}
	for _, statement := range []string{"PRAGMA journal_mode=DELETE", "VACUUM"} {
		if _, e = db.ExecContext(ctx, statement); e != nil {
			return ErrBackup
		}
	}
	var integrity string
	if e = db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); e != nil || integrity != "ok" {
		return ErrBackup
	}
	if e = db.Close(); e != nil {
		return ErrBackup
	}
	return nil
}

func (s *Store) copyOnline(ctx context.Context, path string, file *os.File) error {
	conn, e := s.DB.Conn(ctx)
	if e != nil {
		return ErrBackup
	}
	defer conn.Close()
	// Pin a WAL read snapshot so writes on the controller's separate connection
	// cannot restart every backup step or mix logical revisions.
	tx, e := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return ErrBackup
	}
	defer tx.Rollback()
	var objects int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&objects); e != nil {
		return ErrBackup
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}).String()
	e = conn.Raw(func(raw any) (result error) {
		source, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return ErrBackup
		}
		handle, e := source.NewBackup(uri)
		if e != nil {
			return ErrBackup
		}
		defer func() {
			if finish := handle.Finish(); finish != nil {
				result = ErrBackup
			}
		}()
		for steps := 0; steps < 16384; steps++ {
			if ctx.Err() != nil {
				return ErrBackup
			}
			more, e := handle.Step(128)
			if e != nil {
				return ErrBackup
			}
			info, e := file.Stat()
			if e != nil || info.Size() > maxBackupBytes {
				return ErrBackup
			}
			if !more {
				return nil
			}
		}
		return fmt.Errorf("%w: snapshot work budget exhausted", ErrBackup)
	})
	if e != nil || ctx.Err() != nil {
		return ErrBackup
	}
	return nil
}

// DatabaseSnapshotReceipt describes one local artifact. It deliberately makes
// no application restore, gateway/configuration or tool-manifest claim.
type DatabaseSnapshotReceipt struct {
	Schema   string `json:"schema_version"`
	Status   string `json:"status"`
	Scope    string `json:"scope"`
	Digest   string `json:"database_digest"`
	Bytes    int64  `json:"byte_count"`
	Created  string `json:"created_at"`
	Gateway  bool   `json:"gateway_configuration_captured"`
	Tools    bool   `json:"tool_manifest_captured"`
	Restored bool   `json:"restore_verified"`
}

func (s *Store) BackupSnapshot(ctx context.Context, path string) (DatabaseSnapshotReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out DatabaseSnapshotReceipt
	if e := s.Backup(ctx, path); e != nil {
		return out, e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return out, ErrBackup
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return out, ErrBackup
	}
	defer root.Close()
	before, e := root.Lstat(filepath.Base(path))
	if e != nil || !backupFile(before) || before.Size() > maxBackupBytes {
		return out, ErrBackup
	}
	file, e := openBackupForRead(root, filepath.Base(path))
	if e != nil {
		return out, ErrBackup
	}
	defer file.Close()
	current, e := file.Stat()
	if e != nil || !os.SameFile(before, current) || !backupFile(current) {
		return out, ErrBackup
	}
	hash := sha256.New()
	buffer := make([]byte, 32768)
	var bytes int64
	for {
		if ctx.Err() != nil {
			return out, ErrBackup
		}
		n, e := file.Read(buffer)
		bytes += int64(n)
		if bytes > maxBackupBytes {
			return out, ErrBackup
		}
		hash.Write(buffer[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, ErrBackup
		}
	}
	after, e := file.Stat()
	currentName, ne := root.Lstat(filepath.Base(path))
	if e != nil || ne != nil || !backupFile(currentName) || !os.SameFile(after, currentName) || !backupFile(after) || !os.SameFile(before, after) || bytes != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || ctx.Err() != nil {
		return out, ErrBackup
	}
	return DatabaseSnapshotReceipt{Schema: "1.0", Status: "created", Scope: "controller_database_only", Digest: fmt.Sprintf("sha256:%x", hash.Sum(nil)), Bytes: bytes, Created: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}
