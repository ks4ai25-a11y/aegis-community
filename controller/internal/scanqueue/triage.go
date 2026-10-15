// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type FindingTriageInput struct {
	Schema    string `json:"schema_version"`
	Record    string `json:"record_id"`
	Result    string `json:"result_digest"`
	Expected  int    `json:"expected_revision"`
	State     string `json:"state"`
	Rationale string `json:"rationale"`
}
type FindingTriage struct {
	Schema    string `json:"schema_version"`
	Owner     string `json:"owner_id"`
	Job       string `json:"job_id"`
	Record    string `json:"record_id"`
	Result    string `json:"result_digest"`
	Revision  int    `json:"revision"`
	State     string `json:"state"`
	Rationale string `json:"rationale"`
	Previous  string `json:"previous_digest"`
	Updated   string `json:"updated_at"`
}
type FindingTriageRecord struct {
	Digest   string        `json:"triage_digest"`
	Document FindingTriage `json:"document"`
}

func validTriage(in FindingTriageInput) bool {
	if in.Schema != "1.0" || !digestPattern.MatchString(in.Record) || !digestPattern.MatchString(in.Result) || in.Expected < 0 || in.Expected >= 50 || !utf8.ValidString(in.Rationale) || len(in.Rationale) < 5 || len(in.Rationale) > 512 || strings.TrimSpace(in.Rationale) != in.Rationale {
		return false
	}
	for _, c := range in.Rationale {
		if unicode.IsControl(c) {
			return false
		}
	}
	switch in.State {
	case "suspected", "unverified", "false_positive", "accepted_risk":
		return true
	}
	return false
}
func triageInput(d FindingTriage) FindingTriageInput {
	return FindingTriageInput{Schema: "1.0", Record: d.Record, Result: d.Result, Expected: d.Revision - 1, State: d.State, Rationale: d.Rationale}
}
func triageRecords(ctx context.Context, tx *sql.Tx, owner, job, record, result string) (FindingTriageRecord, []FindingTriageRecord, error) {
	current := FindingTriageRecord{Document: FindingTriage{Schema: "1.0", Owner: owner, Job: job, Record: record, Result: result, State: "suspected"}}
	current.Digest = domain.Digest(current.Document)
	items := []FindingTriageRecord{}
	rows, e := tx.QueryContext(ctx, "SELECT revision,digest,document,request_digest,created_at,idempotency_key,result_digest FROM finding_triage WHERE owner=? AND job=? AND record=? ORDER BY revision LIMIT 51", owner, job, record)
	if e != nil {
		return FindingTriageRecord{}, nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var revision int
		var digest, raw, request, created, key, boundResult string
		if e = rows.Scan(&revision, &digest, &raw, &request, &created, &key, &boundResult); e != nil {
			return FindingTriageRecord{}, nil, e
		}
		var d FindingTriage
		if len(raw) > 2048 || json.Unmarshal([]byte(raw), &d) != nil {
			return FindingTriageRecord{}, nil, ErrConflict
		}
		canonical, e := json.Marshal(d)
		previous := ""
		if current.Document.Revision > 0 {
			previous = current.Digest
		}
		at, te := time.Parse(time.RFC3339Nano, d.Updated)
		if e != nil || string(canonical) != raw || domain.Hash(canonical) != digest || revision != current.Document.Revision+1 || revision > 50 || d.Schema != "1.0" || d.Owner != owner || d.Job != job || d.Record != record || d.Result != result || boundResult != result || d.Revision != revision || d.Previous != previous || d.Updated != created || te != nil || at.IsZero() || !keyPattern.MatchString(key) || !validTriage(triageInput(d)) || domain.Digest(triageInput(d)) != request {
			return FindingTriageRecord{}, nil, ErrConflict
		}
		current = FindingTriageRecord{Digest: digest, Document: d}
		items = append(items, current)
	}
	return current, items, rows.Err()
}
func triageHistory(ctx context.Context, tx *sql.Tx, owner, job, record, result string) (FindingTriageRecord, error) {
	current, _, e := triageRecords(ctx, tx, owner, job, record, result)
	return current, e
}

func (q *Queue) ownedTriageFinding(ctx context.Context, tx *sql.Tx, owner, job, record string) (FindingPage, error) {
	if !digestPattern.MatchString(record) {
		return FindingPage{}, ErrInput
	}
	page, e := q.findingsTx(ctx, tx, owner, job, FindingQuery{Limit: 1}, record)
	if e != nil {
		return FindingPage{}, e
	}
	if len(page.Items) != 1 || page.Items[0].ID != record {
		return FindingPage{}, sql.ErrNoRows
	}
	return page, nil
}
func (q *Queue) FindingTriage(ctx context.Context, owner, job, record string) (FindingTriageRecord, error) {
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return FindingTriageRecord{}, e
	}
	defer tx.Rollback()
	page, e := q.ownedTriageFinding(ctx, tx, owner, job, record)
	if e != nil {
		return FindingTriageRecord{}, e
	}
	return triageHistory(ctx, tx, owner, job, record, page.Result)
}

// SetFindingTriage appends an operator assessment. It cannot change scanner
// evidence, proof strength, verification state or execution admission.
func (q *Queue) SetFindingTriage(ctx context.Context, owner, job, key string, in FindingTriageInput) (FindingTriageRecord, error) {
	if !validTriage(in) || !keyPattern.MatchString(key) {
		return FindingTriageRecord{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return FindingTriageRecord{}, e
	}
	defer tx.Rollback()
	page, e := q.ownedTriageFinding(ctx, tx, owner, job, in.Record)
	if e != nil {
		return FindingTriageRecord{}, e
	}
	if page.Result != in.Result {
		return FindingTriageRecord{}, ErrConflict
	}
	current, e := triageHistory(ctx, tx, owner, job, in.Record, in.Result)
	if e != nil {
		return FindingTriageRecord{}, e
	}
	request := domain.Digest(in)
	var replayJob, replayRecord, replayRequest, replayRaw, replayDigest string
	e = tx.QueryRowContext(ctx, "SELECT job,record,request_digest,document,digest FROM finding_triage WHERE owner=? AND idempotency_key=?", owner, key).Scan(&replayJob, &replayRecord, &replayRequest, &replayRaw, &replayDigest)
	if e == nil {
		if replayJob != job || replayRecord != in.Record || replayRequest != request {
			return FindingTriageRecord{}, ErrConflict
		}
		var d FindingTriage
		if json.Unmarshal([]byte(replayRaw), &d) != nil || d.Revision != in.Expected+1 || domain.Digest(d) != replayDigest || domain.Digest(triageInput(d)) != request {
			return FindingTriageRecord{}, ErrConflict
		}
		return FindingTriageRecord{Digest: replayDigest, Document: d}, nil
	}
	if e != sql.ErrNoRows {
		return FindingTriageRecord{}, e
	}
	if current.Document.Revision != in.Expected {
		return FindingTriageRecord{}, ErrConflict
	}
	d := FindingTriage{Schema: "1.0", Owner: owner, Job: job, Record: in.Record, Result: in.Result, Revision: in.Expected + 1, State: in.State, Rationale: in.Rationale, Updated: q.now().UTC().Format(time.RFC3339Nano)}
	if current.Document.Revision > 0 {
		d.Previous = current.Digest
	}
	b, e := json.Marshal(d)
	if e != nil || len(b) > 2048 {
		return FindingTriageRecord{}, ErrInput
	}
	var total, bytes int
	if e = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(CAST(document AS BLOB))),0) FROM finding_triage").Scan(&total, &bytes); e != nil {
		return FindingTriageRecord{}, e
	}
	if total >= 20000 || bytes+len(b) > 16<<20 {
		return FindingTriageRecord{}, ErrFull
	}
	out := FindingTriageRecord{Digest: domain.Hash(b), Document: d}
	if _, e = tx.ExecContext(ctx, "INSERT INTO finding_triage(job,record,owner,result_digest,revision,idempotency_key,request_digest,digest,document,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", job, in.Record, owner, in.Result, d.Revision, key, request, out.Digest, string(b), d.Updated); e != nil {
		return FindingTriageRecord{}, e
	}
	if e = store.AuditTx(tx, owner, "finding.triage", in.Record, "recorded", map[string]any{"job_id": job, "result_digest": in.Result, "triage_digest": out.Digest, "revision": d.Revision, "state": d.State}); e != nil {
		return FindingTriageRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return FindingTriageRecord{}, e
	}
	return out, nil
}
