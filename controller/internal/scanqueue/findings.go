// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

var ErrResultUnavailable = errors.New("immutable scanner result unavailable")
var ErrFindingBudget = errors.New("finding projection budget exceeded")

type FindingQuery struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Limit    int    `json:"limit"`
	Cursor   string `json:"-"`
}
type FindingEntry struct {
	ID       string               `json:"record_id"`
	Finding  scanevidence.Finding `json:"finding"`
	Receipts []string             `json:"receipt_digests"`
}
type FindingPage struct {
	Schema     string         `json:"schema_version"`
	Owner      string         `json:"owner_id"`
	Job        string         `json:"job_id"`
	Request    string         `json:"request_digest"`
	Result     string         `json:"result_digest"`
	Snapshot   string         `json:"snapshot_digest"`
	Status     string         `json:"status"`
	Partial    bool           `json:"has_partial"`
	Stale      bool           `json:"has_stale_database"`
	ToolError  bool           `json:"has_tool_error"`
	ToolClaims int            `json:"tool_claims"`
	Distinct   int            `json:"distinct_static_claims"`
	Matching   int            `json:"matching_static_claims"`
	Items      []FindingEntry `json:"items"`
	Next       string         `json:"next_cursor"`
}
type findingCursor struct {
	Schema string `json:"schema_version"`
	Result string `json:"result_digest"`
	Query  string `json:"query_digest"`
	Offset int    `json:"offset"`
}

func encodeFindingCursor(c findingCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeFindingCursor(raw string, expected findingCursor, total int) (int, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) > 512 {
		return 0, ErrInput
	}
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil {
		return 0, ErrInput
	}
	var c findingCursor
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return 0, ErrInput
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return 0, ErrInput
	}
	if c.Schema != expected.Schema || c.Result != expected.Result || c.Query != expected.Query || c.Offset <= 0 || c.Offset >= total || encodeFindingCursor(c) != raw {
		return 0, ErrInput
	}
	return c.Offset, nil
}

// Findings derives a bounded view from an owned immutable result and the same
// transaction's revalidated receipts. It neither writes evidence nor promotes
// static tool claims, and never treats unavailable results as an empty scan.
func (q *Queue) Findings(ctx context.Context, owner, id string, in FindingQuery) (FindingPage, error) {
	if in.Limit == 0 {
		in.Limit = 20
	}
	if in.Limit < 1 || in.Limit > 20 || len(in.Cursor) > 512 {
		return FindingPage{}, ErrInput
	}
	switch in.Category {
	case "", "static_pattern", "secret_candidate", "known_vulnerable_dependency":
	default:
		return FindingPage{}, ErrInput
	}
	switch in.Severity {
	case "", "informational", "low", "medium", "high", "critical":
	default:
		return FindingPage{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return FindingPage{}, e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, owner))
	if e != nil {
		return FindingPage{}, e
	}
	result, e := resultTx(tx, j)
	if e != nil {
		if errors.Is(e, ErrConflict) {
			return FindingPage{}, e
		}
		// Distinguish a missing result from a missing owned job, checked above.
		var n int
		if probe := tx.QueryRowContext(ctx, "SELECT count(*) FROM scanner_results WHERE job=?", id).Scan(&n); probe != nil {
			return FindingPage{}, probe
		}
		if n == 0 {
			return FindingPage{}, ErrResultUnavailable
		}
		return FindingPage{}, e
	}
	d := result.Document
	page := FindingPage{Schema: "1.0", Owner: owner, Job: id, Request: j.RequestDigest, Result: result.Digest, Snapshot: d.Snapshot, Status: d.Status, Partial: d.Partial, Stale: d.Stale, ToolError: d.ToolError, ToolClaims: d.FindingClaims, Items: []FindingEntry{}}
	rows, e := tx.QueryContext(ctx, "SELECT document,digest,created_at,tool FROM scanner_receipts WHERE job=? AND owner=? ORDER BY tool", id, owner)
	if e != nil {
		return FindingPage{}, e
	}
	claims := []scanevidence.Finding{}
	refs := map[string]string{}
	for rows.Next() {
		var doc, hash, created, tool string
		if e = rows.Scan(&doc, &hash, &created, &tool); e != nil {
			rows.Close()
			return FindingPage{}, e
		}
		r, e := decodeReceipt(doc, hash, owner, id, j.RequestDigest, tool, created)
		if e != nil {
			rows.Close()
			return FindingPage{}, e
		}
		if len(claims)+len(r.Document.Execution.Result.Findings) > 60000 {
			rows.Close()
			return FindingPage{}, ErrFindingBudget
		}
		claims = append(claims, r.Document.Execution.Result.Findings...)
		refs[tool] = hash
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return FindingPage{}, e
	}
	if e = ctx.Err(); e != nil {
		return FindingPage{}, e
	}
	merged, e := scanevidence.Dedupe(claims)
	if e != nil {
		return FindingPage{}, ErrFindingBudget
	}
	page.Distinct = len(merged)
	filtered := []scanevidence.Finding{}
	for _, f := range merged {
		if (in.Category == "" || f.Category == in.Category) && (in.Severity == "" || f.Severity == in.Severity) {
			filtered = append(filtered, f)
		}
	}
	page.Matching = len(filtered)
	binding := findingCursor{Schema: "1.0", Result: result.Digest, Query: domain.Digest(struct {
		Owner, Job string
		Query      FindingQuery
	}{owner, id, in})}
	offset, e := decodeFindingCursor(in.Cursor, binding, len(filtered))
	if e != nil {
		return FindingPage{}, e
	}
	// Cursor is a canonical seek coordinate, not an authorization token. Every
	// page independently checks owner/result/filter identity and source evidence.
	for i := offset; i < len(filtered) && len(page.Items) < in.Limit; i++ {
		if e = ctx.Err(); e != nil {
			return FindingPage{}, e
		}
		f := filtered[i]
		receiptSet := map[string]bool{}
		for _, p := range f.Provenance {
			ref := refs[p.Tool]
			if ref == "" {
				return FindingPage{}, ErrConflict
			}
			receiptSet[ref] = true
		}
		entry := FindingEntry{ID: findingRecordID(owner, f), Finding: f, Receipts: []string{}}
		for ref := range receiptSet {
			entry.Receipts = append(entry.Receipts, ref)
		}
		sort.Strings(entry.Receipts)
		page.Items = append(page.Items, entry)
		b, e := json.Marshal(page)
		if e != nil {
			return FindingPage{}, e
		}
		// Reserve cursor/envelope overhead inside the standalone clients' 128 KiB.
		if len(b) > 95<<10 {
			page.Items = page.Items[:len(page.Items)-1]
			if len(page.Items) == 0 {
				return FindingPage{}, ErrFindingBudget
			}
			break
		}
	}
	next := offset + len(page.Items)
	if next < len(filtered) {
		binding.Offset = next
		page.Next = encodeFindingCursor(binding)
	}
	return page, nil
}

// Some incomplete dependency coordinates have equal parser IDs but lack the
// PURL needed for a cross-tool merge. Presentation IDs retain that namespace.
func findingRecordID(owner string, f scanevidence.Finding) string {
	tool, rule := "", ""
	if f.Category != "known_vulnerable_dependency" || f.Package == "" {
		tool = f.Provenance[0].Tool
		rule = f.Provenance[0].Rule
	}
	return domain.Digest([]string{"aegis-static-record-v1", owner, f.ID, f.Provenance[0].InputDigest, tool, rule})
}
