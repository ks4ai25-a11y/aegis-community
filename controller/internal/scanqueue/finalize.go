// SPDX-License-Identifier: Apache-2.0
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

const maxSuiteBytes = 16384

type SuiteResult struct {
	Digest   string             `json:"result_digest"`
	Document scanevidence.Suite `json:"document"`
}

// suiteTx derives only from immutable, revalidated receipts and historical map
// identity. Every requested tool is required; no missing tool becomes empty.
func suiteTx(tx *sql.Tx, j Job, stamp string) (scanevidence.Suite, error) {
	d := scanevidence.Suite{Schema: "1.0", Owner: j.Owner, Job: j.ID, Request: j.RequestDigest, App: j.Input.App, Repository: j.Input.Repository, Map: j.Input.MapDigest, Lock: j.LockDigest, Tier: "T0", CleanupRequired: true, Created: stamp, Tools: []scanevidence.SuiteTool{}}
	finished, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil {
		return d, ErrConflict
	}
	m, e := historicalMap(tx, j)
	if e != nil {
		return d, e
	}
	rows, e := tx.Query("SELECT document,digest,created_at,owner,request_digest,tool FROM scanner_receipts WHERE job=? ORDER BY tool", j.ID)
	if e != nil {
		return d, e
	}
	// Close rows before issuing another SQL operation on the single writer.
	var receipts []Receipt
	for rows.Next() {
		var doc, hash, created, owner, request, tool string
		if e = rows.Scan(&doc, &hash, &created, &owner, &request, &tool); e != nil {
			rows.Close()
			return d, e
		}
		if len(receipts) >= 6 || owner != j.Owner || request != j.RequestDigest {
			rows.Close()
			return d, ErrConflict
		}
		r, err := decodeReceipt(doc, hash, owner, j.ID, request, tool, created)
		if err != nil {
			rows.Close()
			return d, err
		}
		receipts = append(receipts, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return d, e
	}
	if len(receipts) != len(j.Input.Tools) {
		return d, ErrConflict
	}
	for i, r := range receipts {
		ex := r.Document.Execution
		if ex.Tool != j.Input.Tools[i] {
			return d, ErrConflict
		}
		until, e := time.Parse(time.RFC3339Nano, r.Created)
		if e != nil || until.After(finished) {
			return d, ErrConflict
		}
		x, e := expectedReceipt(j, m, Pin{ex.Version, ex.Image}, ex.Tool, until)
		if e != nil {
			return d, e
		}
		normalized, e := scanevidence.Normalize(ex, x)
		if e != nil {
			return d, ErrConflict
		}
		original, _ := json.Marshal(ex)
		canonical, _ := json.Marshal(normalized)
		if !bytes.Equal(original, canonical) {
			return d, ErrConflict
		}
		if i == 0 {
			d.Snapshot = ex.Snapshot.Digest
		} else if d.Snapshot != ex.Snapshot.Digest {
			return d, ErrConflict
		}
		d.Tools = append(d.Tools, scanevidence.SuiteTool{Tool: ex.Tool, Receipt: r.Digest, Status: ex.Status, FindingClaims: len(ex.Result.Findings), SBOM: len(ex.Result.SBOM) > 0})
	}
	d.Status, d.FindingClaims, d.Partial, d.Stale, d.ToolError, e = scanevidence.Summarize(d.Tools)
	return d, e
}

func resultTx(tx *sql.Tx, j Job) (SuiteResult, error) {
	var doc, hash, owner, request, stamp string
	e := tx.QueryRow("SELECT document,digest,owner,request_digest,created_at FROM scanner_results WHERE job=?", j.ID).Scan(&doc, &hash, &owner, &request, &stamp)
	if e != nil {
		return SuiteResult{}, e
	}
	if len(doc) > maxSuiteBytes || owner != j.Owner || request != j.RequestDigest || domain.Hash([]byte(doc)) != hash {
		return SuiteResult{}, ErrConflict
	}
	if _, e = time.Parse(time.RFC3339Nano, stamp); e != nil {
		return SuiteResult{}, ErrConflict
	}
	d, e := suiteTx(tx, j, stamp)
	if e != nil {
		return SuiteResult{}, e
	}
	b, _ := json.Marshal(d)
	if !bytes.Equal(b, []byte(doc)) || j.State != d.Status || j.Finished != stamp {
		return SuiteResult{}, ErrConflict
	}
	return SuiteResult{Digest: hash, Document: d}, nil
}

// Finalize derives a terminal scan result; it never verifies cleanup or releases
// the dispatch slot. Replay is read-only and bound to the original capability.
func (q *Queue) Finalize(l Lease) (SuiteResult, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return SuiteResult{}, e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", l.Job.ID, l.Job.Owner))
	if e != nil {
		return SuiteResult{}, e
	}
	if j.RequestDigest != l.Job.RequestDigest {
		return SuiteResult{}, ErrLease
	}
	if e = workerAuthority(tx, l.Worker, j.Owner, q.now().Unix()); e != nil {
		return SuiteResult{}, e
	}
	var n int
	e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch WHERE job=? AND worker=? AND token_hash=?", j.ID, l.Worker, domain.Hash([]byte(l.Token))).Scan(&n)
	if e != nil {
		return SuiteResult{}, e
	}
	if n != 1 {
		return SuiteResult{}, ErrLease
	}
	old, e := resultTx(tx, j)
	if e == nil {
		return old, nil
	}
	if e != sql.ErrNoRows {
		return SuiteResult{}, e
	}
	j, e = q.live(tx, l)
	if e != nil {
		return SuiteResult{}, e
	}
	stamp := q.now().UTC().Format(time.RFC3339Nano)
	d, e := suiteTx(tx, j, stamp)
	if e != nil {
		return SuiteResult{}, e
	}
	b, e := json.Marshal(d)
	if e != nil || len(b) > maxSuiteBytes {
		return SuiteResult{}, ErrInput
	}
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_results").Scan(&count); e != nil {
		return SuiteResult{}, e
	}
	if count >= 1000 {
		return SuiteResult{}, ErrFull
	}
	hash := domain.Hash(b)
	if _, e = tx.Exec("INSERT INTO scanner_results VALUES(?,?,?,?,?,?)", j.ID, j.Owner, j.RequestDigest, hash, string(b), stamp); e != nil {
		return SuiteResult{}, e
	}
	code := ""
	if d.ToolError {
		code = "SCANNER_EXECUTION_FAILED"
	}
	if _, e = tx.Exec("UPDATE scanner_jobs SET state=?,finished_at=?,error_code=? WHERE id=?", d.Status, stamp, code, j.ID); e != nil {
		return SuiteResult{}, e
	}
	if _, e = tx.Exec("UPDATE scanner_dispatch SET state='cleanup_required' WHERE slot=1 AND job=?", j.ID); e != nil {
		return SuiteResult{}, e
	}
	if e = store.AuditTx(tx, j.Owner, "scanner.finished", j.ID, d.Status, map[string]any{"result_digest": hash, "request_digest": j.RequestDigest, "finding_claims": d.FindingClaims, "has_partial": d.Partial, "has_stale_database": d.Stale, "has_tool_error": d.ToolError, "cleanup_confirmed": false, "error_code": code}); e != nil {
		return SuiteResult{}, e
	}
	if e = tx.Commit(); e != nil {
		return SuiteResult{}, e
	}
	return SuiteResult{Digest: hash, Document: d}, nil
}

// Result is owner-scoped and verifies the immutable index against its receipts.
func (q *Queue) Result(owner, id string) (SuiteResult, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return SuiteResult{}, e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, owner))
	if e != nil {
		return SuiteResult{}, e
	}
	return resultTx(tx, j)
}
