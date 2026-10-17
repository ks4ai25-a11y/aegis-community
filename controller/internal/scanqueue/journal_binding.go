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

const journalBindingKey = "scanner_engine_journal_binding"

func (q *Queue) journalBindingTx(tx *sql.Tx, owner string, base scanevidence.EngineBindingRecord) (scanevidence.JournalBindingRecord, error) {
	var raw string
	if e := tx.QueryRow("SELECT value FROM settings WHERE key=?", journalBindingKey).Scan(&raw); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	var out scanevidence.JournalBindingRecord
	if len(raw) > 2048 || json.Unmarshal([]byte(raw), &out) != nil || !out.Valid(owner, base) {
		return scanevidence.JournalBindingRecord{}, ErrConflict
	}
	canonical, e := json.Marshal(out)
	created, ce := time.Parse(time.RFC3339Nano, out.Document.Created)
	if e != nil || !bytes.Equal(canonical, []byte(raw)) || ce != nil || created.After(q.now()) {
		return scanevidence.JournalBindingRecord{}, ErrConflict
	}
	return out, nil
}

// BindJournal is a local operator operation. An existing engine scope is
// required, and the first journal binding cannot be added over any dispatch.
func (q *Queue) BindJournal(owner, root, namespace string) (scanevidence.JournalBindingRecord, error) {
	if owner == "" || len(owner) > 128 || !digestPattern.MatchString(root) || !digestPattern.MatchString(namespace) {
		return scanevidence.JournalBindingRecord{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	defer tx.Rollback()
	base, e := q.engineBindingTx(tx, owner)
	if e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	old, e := q.journalBindingTx(tx, owner, base)
	if e == nil {
		if old.Document.Root != root || old.Document.Namespace != namespace {
			return scanevidence.JournalBindingRecord{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return scanevidence.JournalBindingRecord{}, e
	}
	var occupied int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&occupied); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	if occupied != 0 {
		return scanevidence.JournalBindingRecord{}, ErrCleanup
	}
	d := scanevidence.JournalBinding{Schema: "1.0", Owner: owner, EngineBinding: base.Digest, Root: root, Namespace: namespace, Created: q.now().UTC().Format(time.RFC3339Nano)}
	out := scanevidence.JournalBindingRecord{Digest: domain.Digest(d), Document: d}
	if !out.Valid(owner, base) {
		return scanevidence.JournalBindingRecord{}, ErrConflict
	}
	raw, e := json.Marshal(out)
	if e != nil {
		return scanevidence.JournalBindingRecord{}, ErrConflict
	}
	if _, e = tx.Exec("INSERT INTO settings VALUES(?,?)", journalBindingKey, string(raw)); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.journal_bind", out.Digest, "BOUND", map[string]any{"engine_binding_digest": base.Digest, "journal_root_digest": root, "journal_namespace_digest": namespace, "all_engine_writes_mediated": false, "cleanup_release_authorized": false}); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	return out, nil
}

func (q *Queue) JournalBindingForWorker(worker, owner string) (scanevidence.JournalBindingRecord, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	defer tx.Rollback()
	if e = workerAuthority(tx, worker, owner, q.now().Unix()); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	base, e := q.engineBindingTx(tx, owner)
	if e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	out, e := q.journalBindingTx(tx, owner, base)
	if e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	return out, nil
}
