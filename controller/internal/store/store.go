// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"aegis.local/controller/internal/domain"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	DB   *sql.DB
	Path string
	mu   sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS owners(id TEXT PRIMARY KEY,password TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,owner TEXT NOT NULL,csrf TEXT NOT NULL,created INTEGER NOT NULL,seen INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS policies(digest TEXT PRIMARY KEY,parent TEXT NOT NULL,document TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,actor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,at TEXT NOT NULL,request TEXT NOT NULL,source_key TEXT UNIQUE NOT NULL,document TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_at ON events(at,seq);
CREATE INDEX IF NOT EXISTS events_request ON events(request);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,summary TEXT NOT NULL,opened_at TEXT NOT NULL,state TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS incident_events(incident TEXT NOT NULL REFERENCES incidents(id),event TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,PRIMARY KEY(incident,event));
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,document TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS idempotency(key TEXT PRIMARY KEY,content_hash TEXT NOT NULL,response TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(digest TEXT PRIMARY KEY,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,state TEXT NOT NULL,document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cursors(source TEXT PRIMARY KEY,offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,document TEXT NOT NULL,token_hash TEXT NOT NULL DEFAULT '',expires INTEGER NOT NULL DEFAULT 0,epoch INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invites(id TEXT PRIMARY KEY,connection TEXT NOT NULL,challenge_hash TEXT NOT NULL,expires INTEGER NOT NULL,fingerprint TEXT NOT NULL DEFAULT '',confirmed INTEGER NOT NULL DEFAULT 0,consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS consents(id TEXT PRIMARY KEY,connection TEXT NOT NULL,incident TEXT NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS handoffs(id TEXT PRIMARY KEY,connection TEXT NOT NULL,incident TEXT NOT NULL,document TEXT NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS drafts(id TEXT PRIMARY KEY,connection TEXT NOT NULL,incident TEXT NOT NULL,state TEXT NOT NULL,document TEXT NOT NULL,hash TEXT NOT NULL,key TEXT NOT NULL,UNIQUE(connection,key));
`

const RestorePending = ".restore-pending"

func refusePendingRestore(path string) error {
	if _, e := os.Lstat(filepath.Join(filepath.Dir(path), RestorePending)); !os.IsNotExist(e) {
		return fmt.Errorf("offline restore is incomplete; controller state remains quarantined")
	}
	return nil
}

func Open(path string) (*Store, error) {
	if e := refusePendingRestore(path); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, Path: path}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_size_limit=16777216"} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, e
		}
	}
	os.Chmod(path, 0600)
	if e = migrate(db); e != nil {
		db.Close()
		return nil, e
	}
	if _, e = s.Get("active"); e == sql.ErrNoRows {
		p := domain.Initial()
		b, _ := json.Marshal(p)
		d := domain.Digest(p)
		tx, e := db.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		_, e = tx.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", d, "", string(b), "ACTIVE", domain.Now(), "system")
		if e == nil {
			_, e = tx.Exec("INSERT INTO settings VALUES('active',?)", d)
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			return nil, e
		}
	}
	return s, nil
}
func (s *Store) Get(k string) (string, error) {
	var v string
	e := s.DB.QueryRow("SELECT value FROM settings WHERE key=?", k).Scan(&v)
	return v, e
}
func (s *Store) Set(k, v string) error {
	_, e := s.DB.Exec("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v)
	return e
}
func (s *Store) Active() (domain.Policy, string, error) {
	d, e := s.Get("active")
	if e != nil {
		return domain.Policy{}, "", e
	}
	p, e := s.Policy(d)
	return p, d, e
}
func (s *Store) Policy(d string) (domain.Policy, error) {
	var raw string
	var p domain.Policy
	e := s.DB.QueryRow("SELECT document FROM policies WHERE digest=?", d).Scan(&raw)
	if e == nil {
		e = json.Unmarshal([]byte(raw), &p)
	}
	return p, e
}
func (s *Store) Audit(actor, action, object, result string, data any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = AuditTx(tx, actor, action, object, result, data); e != nil {
		return e
	}
	return tx.Commit()
}

// AuditTx appends the authorization record in the caller's state transaction.
func AuditTx(tx *sql.Tx, actor, action, object, result string, data any) error {
	prev := ""
	e := tx.QueryRow("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").Scan(&prev)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	b, e := json.Marshal(map[string]any{"record_id": domain.ID(), "occurred_at": domain.Now(), "actor_id": actor, "action": action, "object_id": object, "result": result, "data": data})
	if e != nil {
		return e
	}
	h := domain.Hash(append([]byte("aegis-audit-v1\x00"+prev), b...))
	_, e = tx.Exec("INSERT INTO audit(document,previous,hash)VALUES(?,?,?)", string(b), prev, h)
	return e
}
func (s *Store) VerifyAudit() error {
	return s.VerifyAuditContext(context.Background())
}
func (s *Store) VerifyAuditContext(ctx context.Context) error {
	rows, e := s.DB.QueryContext(ctx, "SELECT document,previous,hash FROM audit ORDER BY seq")
	if e != nil {
		return e
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var b, p, h string
		if e = rows.Scan(&b, &p, &h); e != nil {
			return e
		}
		if p != prev || h != domain.Hash(append([]byte("aegis-audit-v1\x00"+p), []byte(b)...)) {
			return fmt.Errorf("audit chain mismatch")
		}
		prev = h
	}
	return rows.Err()
}
