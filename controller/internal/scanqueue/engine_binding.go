// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"bytes"
	"database/sql"
	"encoding/json"
	"time"
)

const engineBindingKey = "scanner_engine_binding"

func (q *Queue) engineBindingTx(tx *sql.Tx, owner string) (scanevidence.EngineBindingRecord, error) {
	var raw string
	if e := tx.QueryRow("SELECT value FROM settings WHERE key=?", engineBindingKey).Scan(&raw); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	var out scanevidence.EngineBindingRecord
	if len(raw) > 2048 || json.Unmarshal([]byte(raw), &out) != nil || !out.Valid(owner) {
		return out, ErrConflict
	}
	created, e := time.Parse(time.RFC3339Nano, out.Document.Created)
	if e != nil || created.After(q.now()) {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(canonical, []byte(raw)) {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	var bound string
	if e = tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&bound); e != nil || bound != owner {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	return out, nil
}

// BindEngine is reserved for the local operator CLI. No HTTP path can call it.
// An exact repeat returns the original record; replacement/reset is unavailable.
func (q *Queue) BindEngine(owner, engine, registry string) (scanevidence.EngineBindingRecord, error) {
	if owner == "" || len(owner) > 128 || !digestPattern.MatchString(engine) || !digestPattern.MatchString(registry) {
		return scanevidence.EngineBindingRecord{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	defer tx.Rollback()
	old, e := q.engineBindingTx(tx, owner)
	if e == nil {
		if old.Document.Engine != engine || old.Document.Registry != registry {
			return scanevidence.EngineBindingRecord{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return scanevidence.EngineBindingRecord{}, e
	}
	var bound string
	if e = tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&bound); e != nil || bound != owner {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	var repos, occupied int
	if e = tx.QueryRow("SELECT count(*) FROM repositories WHERE owner=?", owner).Scan(&repos); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	if repos == 0 {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	if e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&occupied); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	if occupied != 0 {
		return scanevidence.EngineBindingRecord{}, ErrCleanup
	}
	d := scanevidence.EngineBinding{Schema: "1.0", Owner: owner, Engine: engine, Registry: registry, Created: q.now().UTC().Format(time.RFC3339Nano)}
	out := scanevidence.EngineBindingRecord{Digest: domain.Digest(d), Document: d}
	raw, e := json.Marshal(out)
	if e != nil || !out.Valid(owner) {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	if _, e = tx.Exec("INSERT INTO settings(key,value) VALUES(?,?)", engineBindingKey, string(raw)); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.engine_bind", out.Digest, "BOUND", map[string]any{"engine_digest": engine, "registry_digest": registry, "all_engine_writes_mediated": false, "cleanup_release_authorized": false}); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	return out, nil
}

// EngineBindingForWorker authenticates again in the read transaction to close
// the initial channel authentication/revocation gap. It never creates a binding.
func (q *Queue) EngineBindingForWorker(worker, owner string) (scanevidence.EngineBindingRecord, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	defer tx.Rollback()
	if e = workerAuthority(tx, worker, owner, q.now().Unix()); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	out, e := q.engineBindingTx(tx, owner)
	if e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	created, e := time.Parse(time.RFC3339Nano, out.Document.Created)
	if e != nil || created.After(q.now()) {
		return scanevidence.EngineBindingRecord{}, ErrConflict
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	return out, nil
}
