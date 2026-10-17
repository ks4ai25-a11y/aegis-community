// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/store"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// Operator approval of offline advisory databases (ADR 068). An approval names
// the exact database digest the operator verified for a tool. When a job is
// queued, the current fresh approvals are written into its request, so receipt
// validation later is reproducible: only a scan that used that exact,
// still-fresh database reports "completed" instead of "completed_stale_db".

const databaseApprovalKey = "scanner_database_approvals"

// DatabaseMaxAge matches the scanner's default freshness window.
var DatabaseMaxAge = 7 * 24 * time.Hour

var ErrDatabase = errors.New("invalid advisory database approval")

type DatabaseApproval struct {
	Tool       string `json:"tool_id"`
	Digest     string `json:"database_digest"`
	BuiltAt    string `json:"upstream_built_at"`
	ApprovedAt string `json:"approved_at"`
	ApprovedBy string `json:"approved_by"`
}

func databaseTool(t string) bool { return t == "osv_v2" || t == "trivy" }

func (q *Queue) DatabaseApprovals() ([]DatabaseApproval, error) {
	v, e := q.S.Get(databaseApprovalKey)
	if e == sql.ErrNoRows {
		return []DatabaseApproval{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []DatabaseApproval{}
	if json.Unmarshal([]byte(v), &out) != nil {
		return nil, ErrDatabase
	}
	return out, nil
}

// ApproveDatabase records (or replaces) the approval for one tool, atomically
// with its audit record.
func (q *Queue) ApproveDatabase(actor, tool, digest, builtAt string) (DatabaseApproval, error) {
	built, e := time.Parse(time.RFC3339, builtAt)
	if !databaseTool(tool) || !digestPattern.MatchString(digest) || e != nil || built.After(q.now().Add(time.Hour)) {
		return DatabaseApproval{}, ErrDatabase
	}
	list, e := q.DatabaseApprovals()
	if e != nil {
		return DatabaseApproval{}, e
	}
	a := DatabaseApproval{Tool: tool, Digest: digest, BuiltAt: built.UTC().Format(time.RFC3339), ApprovedAt: q.now().UTC().Format(time.RFC3339), ApprovedBy: actor}
	kept := []DatabaseApproval{a}
	for _, x := range list {
		if x.Tool != tool {
			kept = append(kept, x)
		}
	}
	return a, q.saveApprovals(kept, actor, "scanner.database_approved", tool, map[string]any{"database_digest": digest, "upstream_built_at": a.BuiltAt})
}

func (q *Queue) RevokeDatabase(actor, tool string) error {
	if !databaseTool(tool) {
		return ErrDatabase
	}
	list, e := q.DatabaseApprovals()
	if e != nil {
		return e
	}
	kept := []DatabaseApproval{}
	for _, x := range list {
		if x.Tool != tool {
			kept = append(kept, x)
		}
	}
	return q.saveApprovals(kept, actor, "scanner.database_revoked", tool, nil)
}

func (q *Queue) saveApprovals(list []DatabaseApproval, actor, action, tool string, data any) error {
	sort.Slice(list, func(i, j int) bool { return list[i].Tool < list[j].Tool })
	b, _ := json.Marshal(list)
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", databaseApprovalKey, string(b)); e != nil {
		return e
	}
	if e = store.AuditTx(tx, actor, action, tool, "ok", data); e != nil {
		return e
	}
	return tx.Commit()
}

// freshApprovals returns the approved digests that are still within the
// freshness window, for the tools a job requests.
func (q *Queue) freshApprovals(tools []string) map[string]string {
	list, e := q.DatabaseApprovals()
	if e != nil {
		return nil
	}
	out := map[string]string{}
	for _, a := range list {
		built, e := time.Parse(time.RFC3339, a.BuiltAt)
		if e != nil || q.now().Sub(built) > DatabaseMaxAge {
			continue
		}
		for _, t := range tools {
			if t == a.Tool {
				out[t] = a.Digest
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
