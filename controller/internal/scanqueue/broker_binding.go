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

const brokerBindingKey = "scanner_engine_broker_binding"

func (q *Queue) brokerBindingTx(tx *sql.Tx, owner string) (scanevidence.BrokerBindingRecord, error) {
	var raw string
	if e := tx.QueryRow("SELECT value FROM settings WHERE key=?", brokerBindingKey).Scan(&raw); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	base, e := q.engineBindingTx(tx, owner)
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, ErrConflict
	}
	journal, e := q.journalBindingTx(tx, owner, base)
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, ErrConflict
	}
	var out scanevidence.BrokerBindingRecord
	if len(raw) > 2048 || json.Unmarshal([]byte(raw), &out) != nil || !out.Valid(owner, base, journal) {
		return scanevidence.BrokerBindingRecord{}, ErrConflict
	}
	canonical, e := json.Marshal(out)
	created, ce := time.Parse(time.RFC3339Nano, out.Document.Created)
	if e != nil || !bytes.Equal([]byte(raw), canonical) || ce != nil || created.After(q.now()) {
		return scanevidence.BrokerBindingRecord{}, ErrConflict
	}
	return out, nil
}
func (q *Queue) matchBrokerTx(tx *sql.Tx, worker, owner string) error {
	r, e := q.brokerBindingTx(tx, owner)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	if r.Document.Worker != worker {
		return ErrLease
	}
	return nil
}
func (q *Queue) BindBroker(owner, worker string) (scanevidence.BrokerBindingRecord, error) {
	if owner == "" || len(owner) > 128 || !workerPattern.MatchString(worker) {
		return scanevidence.BrokerBindingRecord{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	defer tx.Rollback()
	base, e := q.engineBindingTx(tx, owner)
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	journal, e := q.journalBindingTx(tx, owner, base)
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	old, e := q.brokerBindingTx(tx, owner)
	if e == nil {
		if old.Document.Worker != worker {
			return scanevidence.BrokerBindingRecord{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return scanevidence.BrokerBindingRecord{}, e
	}
	if e = workerAuthority(tx, worker, owner, q.now().Unix()); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	var occupied int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&occupied); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	if occupied != 0 {
		return scanevidence.BrokerBindingRecord{}, ErrCleanup
	}
	d := scanevidence.BrokerBinding{Schema: "1.0", Owner: owner, Worker: worker, Journal: journal.Digest, Created: q.now().UTC().Format(time.RFC3339Nano)}
	out := scanevidence.BrokerBindingRecord{Digest: domain.Digest(d), Document: d}
	if !out.Valid(owner, base, journal) {
		return scanevidence.BrokerBindingRecord{}, ErrConflict
	}
	raw, e := json.Marshal(out)
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, ErrConflict
	}
	if _, e = tx.Exec("INSERT INTO settings VALUES(?,?)", brokerBindingKey, string(raw)); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.broker_bind", out.Digest, "BOUND", map[string]any{"worker_id": worker, "journal_binding_digest": journal.Digest, "all_engine_writes_mediated": false, "cleanup_release_authorized": false}); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	return out, nil
}
func (q *Queue) BrokerBindingForWorker(worker, owner string) (scanevidence.BrokerBindingRecord, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	defer tx.Rollback()
	if e = workerAuthority(tx, worker, owner, q.now().Unix()); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	out, e := q.brokerBindingTx(tx, owner)
	if e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	if out.Document.Worker != worker {
		return scanevidence.BrokerBindingRecord{}, ErrLease
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	return out, nil
}
