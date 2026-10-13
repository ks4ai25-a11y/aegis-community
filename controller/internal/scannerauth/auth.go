// SPDX-License-Identifier: Apache-2.0
// Package scannerauth defines a separate worker role. Browser owner sessions
// cannot create this role. Enrollment is reserved for a local operator channel.
package scannerauth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

var ErrDenied = errors.New("scanner worker authentication unavailable")
var ErrConflict = errors.New("scanner worker enrollment conflicts with durable state")
var ErrInput = errors.New("invalid scanner worker enrollment")
var workerID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var tokenFormat = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Registry struct {
	S   *store.Store
	Now func() time.Time
}
type Worker struct {
	ID      string `json:"worker_id"`
	Owner   string `json:"owner_id"`
	State   string `json:"state"`
	Expires string `json:"expires_at"`
	Created string `json:"created_at"`
}
type Enrollment struct {
	Worker Worker
	Token  string `json:"-"`
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
func (r *Registry) Enroll(owner, id string, minutes int) (Enrollment, error) {
	return r.enroll(owner, id, minutes, nil)
}
func (r *Registry) enroll(owner, id string, minutes int, issue func(string) error) (Enrollment, error) {
	if !workerID.MatchString(id) || owner == "" || len(owner) > 128 || minutes < 1 || minutes > 1440 {
		return Enrollment{}, ErrInput
	}
	bytes := make([]byte, 32)
	if _, e := rand.Read(bytes); e != nil {
		return Enrollment{}, e
	}
	token := hex.EncodeToString(bytes)
	tx, e := r.S.DB.Begin()
	if e != nil {
		return Enrollment{}, e
	}
	defer tx.Rollback()
	var bound string
	if e = tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&bound); e != nil || bound != owner {
		if e != nil && e != sql.ErrNoRows {
			return Enrollment{}, e
		}
		return Enrollment{}, ErrDenied
	}
	var repositories, total, active int
	if e = tx.QueryRow("SELECT count(*) FROM repositories WHERE owner=?", owner).Scan(&repositories); e != nil {
		return Enrollment{}, e
	}
	if repositories == 0 {
		return Enrollment{}, ErrDenied
	}
	var existing int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_workers WHERE id=?", id).Scan(&existing); e != nil {
		return Enrollment{}, e
	}
	if existing != 0 {
		return Enrollment{}, ErrConflict
	}
	if e = tx.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN owner=? AND state='active' AND expires>? THEN 1 ELSE 0 END),0) FROM scanner_workers", owner, r.now().Unix()).Scan(&total, &active); e != nil {
		return Enrollment{}, e
	}
	if total >= 100 || active >= 8 {
		return Enrollment{}, ErrConflict
	}
	now := r.now().UTC()
	expires := now.Add(time.Duration(minutes) * time.Minute)
	w := Worker{id, owner, "active", expires.Format(time.RFC3339), now.Format(time.RFC3339Nano)}
	if _, e = tx.Exec("INSERT INTO scanner_workers VALUES(?,?,?,'active',?,?)", id, owner, domain.Hash([]byte(token)), expires.Unix(), w.Created); e != nil {
		return Enrollment{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.worker_enroll", id, "active", map[string]any{"expires_unix": expires.Unix(), "role": "offline-scanner-worker"}); e != nil {
		return Enrollment{}, e
	}
	if issue != nil {
		if e = issue(token); e != nil {
			return Enrollment{}, e
		}
	}
	if e = tx.Commit(); e != nil {
		return Enrollment{}, e
	}
	return Enrollment{w, token}, nil
}
func (r *Registry) Authenticate(token string) (Worker, error) {
	if !tokenFormat.MatchString(token) {
		return Worker{}, ErrDenied
	}
	var w Worker
	var expires int64
	e := r.S.DB.QueryRow("SELECT id,owner,state,expires,created_at FROM scanner_workers WHERE token_hash=? AND state='active' AND expires>?", domain.Hash([]byte(token)), r.now().Unix()).Scan(&w.ID, &w.Owner, &w.State, &expires, &w.Created)
	if e == sql.ErrNoRows {
		return Worker{}, ErrDenied
	}
	if e != nil {
		return Worker{}, e
	}
	// Mount authority remains live; enrollment does not transfer mount ownership.
	var bound string
	if e = r.S.DB.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&bound); e != nil || bound != w.Owner {
		return Worker{}, ErrDenied
	}
	w.Expires = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	return w, nil
}
func (r *Registry) Revoke(owner, id string) error {
	tx, e := r.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state string
	if e = tx.QueryRow("SELECT state FROM scanner_workers WHERE id=? AND owner=?", id, owner).Scan(&state); e != nil {
		return e
	}
	if state == "revoked" {
		return nil
	}
	if _, e = tx.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=? AND owner=?", id, owner); e != nil {
		return e
	}
	// Cancellation is immediate authority withdrawal, not a cleanup assertion.
	if _, e = tx.Exec("UPDATE scanner_jobs SET cancel_requested=1,error_code='WORKER_REVOKED' WHERE owner=? AND state='running' AND id IN (SELECT job FROM scanner_dispatch WHERE worker=?)", owner, id); e != nil {
		return e
	}
	if e = store.AuditTx(tx, owner, "scanner.worker_revoke", id, "revoked", nil); e != nil {
		return e
	}
	return tx.Commit()
}
