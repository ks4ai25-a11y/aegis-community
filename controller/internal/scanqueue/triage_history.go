// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"context"
	"encoding/json"
)

type FindingTriageHistoryDocument struct {
	Schema   string                `json:"schema_version"`
	Scope    string                `json:"assessment_scope"`
	Owner    string                `json:"owner_id"`
	Job      string                `json:"job_id"`
	Record   string                `json:"record_id"`
	Result   string                `json:"result_digest"`
	Baseline string                `json:"baseline_digest"`
	Head     string                `json:"head_digest"`
	Count    int                   `json:"revision_count"`
	Complete bool                  `json:"complete"`
	Items    []FindingTriageRecord `json:"items"`
}
type FindingTriageHistory struct {
	Digest   string                       `json:"history_digest"`
	Document FindingTriageHistoryDocument `json:"document"`
}

// FindingHistory exports the complete bounded decision chain in one read
// transaction with the exact owned immutable result and receipts. It never
// treats an assessment as stronger scanner evidence or carries it across jobs.
func (q *Queue) FindingHistory(ctx context.Context, owner, job, record, result string) (FindingTriageHistory, error) {
	if !digestPattern.MatchString(record) || !digestPattern.MatchString(result) {
		return FindingTriageHistory{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return FindingTriageHistory{}, e
	}
	defer tx.Rollback()
	page, e := q.ownedTriageFinding(ctx, tx, owner, job, record)
	if e != nil {
		return FindingTriageHistory{}, e
	}
	if page.Result != result {
		return FindingTriageHistory{}, ErrConflict
	}
	current, items, e := triageRecords(ctx, tx, owner, job, record, result)
	if e != nil {
		return FindingTriageHistory{}, e
	}
	baseline := FindingTriage{Schema: "1.0", Owner: owner, Job: job, Record: record, Result: result, State: "suspected"}
	document := FindingTriageHistoryDocument{Schema: "1.0", Scope: "owner_review_only", Owner: owner, Job: job, Record: record, Result: result, Baseline: domain.Digest(baseline), Head: current.Digest, Count: current.Document.Revision, Complete: true, Items: items}
	out := FindingTriageHistory{Digest: domain.Digest(document), Document: document}
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > 120<<10 {
		return FindingTriageHistory{}, ErrFindingBudget
	}
	if e = ctx.Err(); e != nil {
		return FindingTriageHistory{}, e
	}
	return out, nil
}
