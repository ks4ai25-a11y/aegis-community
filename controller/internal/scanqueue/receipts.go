// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"database/sql"
	"encoding/json"
	"time"
)

const maxReceiptBytes = scanevidence.MaxOutput + 4096
const maxLedgerBytes = 64 << 20

type Pin struct{ Version, Image string }
type ReceiptDocument struct {
	Schema    string                 `json:"schema_version"`
	Owner     string                 `json:"owner_id"`
	Job       string                 `json:"job_id"`
	Request   string                 `json:"request_digest"`
	Execution scanevidence.Execution `json:"execution"`
}
type Receipt struct {
	Digest   string          `json:"digest"`
	Document ReceiptDocument `json:"document"`
	Created  string          `json:"created_at"`
}

func decodeReceipt(document, hash, owner, job, request, tool, created string) (Receipt, error) {
	var d ReceiptDocument
	if len(document) > maxReceiptBytes || domain.Hash([]byte(document)) != hash || json.Unmarshal([]byte(document), &d) != nil || d.Schema != "1.0" || d.Owner != owner || d.Job != job || d.Request != request || d.Execution.Tool != tool {
		return Receipt{}, ErrConflict
	}
	if _, e := time.Parse(time.RFC3339Nano, created); e != nil {
		return Receipt{}, ErrConflict
	}
	return Receipt{hash, d, created}, nil
}
func historicalMap(tx *sql.Tx, j Job) (source.Map, error) {
	var doc string
	var m source.Map
	e := tx.QueryRow("SELECT document FROM application_maps WHERE repository=? AND digest=?", j.Input.Repository, j.Input.MapDigest).Scan(&doc)
	if e != nil {
		return m, e
	}
	if len(doc) > 60000 || json.Unmarshal([]byte(doc), &m) != nil {
		return m, ErrConflict
	}
	return m, nil
}
func expectedReceipt(j Job, m source.Map, pin Pin, tool string, until time.Time) (scanevidence.Expected, error) {
	started, e := time.Parse(time.RFC3339Nano, j.Created)
	if e != nil {
		return scanevidence.Expected{}, ErrConflict
	}
	return scanevidence.Expected{Tools: j.Input.Tools, App: j.Input.App, Repository: j.Input.Repository, LockDigest: j.LockDigest, Tool: tool, Version: pin.Version, Image: pin.Image, Timeout: j.Input.Duration, Map: m, NotBefore: started, NotAfter: until}, nil
}

// RecordReceipt validates and commits a single immutable normalized tool receipt
// with its audit event. It never marks the job complete or releases admission.
func (q *Queue) RecordReceipt(l Lease, in scanevidence.Execution) (Receipt, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return Receipt{}, e
	}
	defer tx.Rollback()
	// Idempotent replay binds the original worker capability, durable job identity
	// and active enrollment, but cannot renew expired execution or rewrite evidence.
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", l.Job.ID, l.Job.Owner))
	if e != nil {
		return Receipt{}, e
	}
	if j.RequestDigest != l.Job.RequestDigest {
		return Receipt{}, ErrLease
	}
	if e = workerAuthority(tx, l.Worker, j.Owner, q.now().Unix()); e != nil {
		return Receipt{}, e
	}
	var n int
	e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch WHERE job=? AND worker=? AND token_hash=?", j.ID, l.Worker, domain.Hash([]byte(l.Token))).Scan(&n)
	if e != nil {
		return Receipt{}, e
	}
	if n != 1 {
		return Receipt{}, ErrLease
	}
	var document, hash, created, owner, request string
	e = tx.QueryRow("SELECT document,digest,created_at,owner,request_digest FROM scanner_receipts WHERE job=? AND tool=?", j.ID, in.Tool).Scan(&document, &hash, &created, &owner, &request)
	var old Receipt
	replay := e == nil
	if e != nil && e != sql.ErrNoRows {
		return Receipt{}, e
	}
	var m source.Map
	var pin Pin
	until := q.now()
	if replay {
		if owner != j.Owner || request != j.RequestDigest {
			return Receipt{}, ErrConflict
		}
		old, e = decodeReceipt(document, hash, owner, j.ID, request, in.Tool, created)
		if e != nil {
			return Receipt{}, e
		}
		m, e = historicalMap(tx, j)
		if e != nil {
			return Receipt{}, e
		}
		pin = Pin{old.Document.Execution.Version, old.Document.Execution.Image}
		until, _ = time.Parse(time.RFC3339Nano, created)
	} else {
		if _, e = q.live(tx, l); e != nil {
			return Receipt{}, e
		}
		m, e = q.authority(tx, j)
		if e != nil {
			return Receipt{}, e
		}
		var ok bool
		pin, ok = q.Pins[in.Tool]
		if !ok {
			return Receipt{}, ErrInput
		}
	}
	expected, e := expectedReceipt(j, m, pin, in.Tool, until)
	if e != nil {
		return Receipt{}, e
	}
	normalized, e := scanevidence.Normalize(in, expected)
	if e != nil {
		return Receipt{}, ErrInput
	}
	d := ReceiptDocument{"1.0", j.Owner, j.ID, j.RequestDigest, normalized}
	b, e := json.Marshal(d)
	if e != nil || len(b) > maxReceiptBytes {
		return Receipt{}, ErrInput
	}
	identity := domain.Hash(b)
	if replay {
		if identity != old.Digest {
			return Receipt{}, ErrConflict
		}
		return old, nil
	}
	var count, total int64
	if e = tx.QueryRow("SELECT count(*),coalesce(sum(length(CAST(document AS BLOB))),0) FROM scanner_receipts").Scan(&count, &total); e != nil {
		return Receipt{}, e
	}
	if count >= 6000 || total+int64(len(b)) > maxLedgerBytes {
		return Receipt{}, ErrFull
	}
	stamp := q.now().UTC().Format(time.RFC3339Nano)
	if _, e = tx.Exec("INSERT INTO scanner_receipts VALUES(?,?,?,?,?,?,?)", j.ID, in.Tool, j.Owner, j.RequestDigest, identity, string(b), stamp); e != nil {
		return Receipt{}, e
	}
	if e = store.AuditTx(tx, j.Owner, "scanner.receipt", j.ID, "accepted", map[string]any{"tool_id": in.Tool, "receipt_digest": identity, "request_digest": j.RequestDigest, "tool_status": normalized.Status, "finding_count": len(normalized.Result.Findings), "evidence_tier": "T0", "cleanup_confirmed": false}); e != nil {
		return Receipt{}, e
	}
	if e = tx.Commit(); e != nil {
		return Receipt{}, e
	}
	return Receipt{identity, d, stamp}, nil
}

// Receipts reads only an owner's durable job, verifies stored content/relational
// identity and returns at most the six immutable per-tool records.
func (q *Queue) Receipts(owner, id string) ([]Receipt, error) {
	j, e := q.Get(owner, id)
	if e != nil {
		return nil, e
	}
	rows, e := q.S.DB.Query("SELECT document,digest,created_at,owner,request_digest,tool FROM scanner_receipts WHERE job=? AND owner=? ORDER BY tool", id, owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Receipt{}
	for rows.Next() {
		var doc, hash, created, bound, request, tool string
		if e = rows.Scan(&doc, &hash, &created, &bound, &request, &tool); e != nil {
			return nil, e
		}
		if request != j.RequestDigest || bound != owner || len(out) >= 6 {
			return nil, ErrConflict
		}
		r, e := decodeReceipt(doc, hash, bound, id, request, tool, created)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
