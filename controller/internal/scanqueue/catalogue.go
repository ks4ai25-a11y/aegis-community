// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"fmt"
	"aegis.local/controller/internal/domain"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"
)

var ErrCatalogueChanged = errors.New("retained result set changed; restart catalogue")

type CatalogueQuery struct {
	Repository string `json:"repository_id,omitempty"`
	Category   string `json:"category,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	Limit      int    `json:"limit"`
	Cursor     string `json:"-"`
}
type CataloguePage struct {
	Schema      string       `json:"schema_version"`
	Owner       string       `json:"owner_id"`
	Scope       string       `json:"scope"`
	Set         string       `json:"result_set_digest"`
	Results     int          `json:"retained_result_count"`
	Unavailable int          `json:"jobs_without_result"`
	Index       int          `json:"result_index"`
	Result      *SuiteResult `json:"result,omitempty"`
	Findings    *FindingPage `json:"findings,omitempty"`
	Next        string       `json:"next_cursor"`
}
type catalogueRow struct {
	Job     string `json:"job_id"`
	Digest  string `json:"result_digest"`
	Created string `json:"created_at"`
	stamp   time.Time
}
type catalogueCursor struct {
	Schema string `json:"schema_version"`
	Set    string `json:"result_set_digest"`
	Index  int    `json:"result_index"`
	Inner  string `json:"finding_cursor"`
}

func encodeCatalogueCursor(c catalogueCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeCatalogueCursor(raw, set string, total int) (catalogueCursor, error) {
	c := catalogueCursor{Schema: "1.0", Set: set}
	if raw == "" {
		return c, nil
	}
	if len(raw) > 2048 {
		return c, ErrInput
	}
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil {
		return c, ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, ErrInput
	}
	var extra any
	if d.Decode(&extra) != io.EOF || encodeCatalogueCursor(c) != raw || c.Schema != "1.0" || c.Index < 0 || len(c.Inner) > 512 {
		return c, ErrInput
	}
	if c.Set != set {
		return c, ErrCatalogueChanged
	}
	if c.Index >= total || c.Index == 0 && c.Inner == "" {
		return c, ErrInput
	}
	return c, nil
}

// Catalogue walks all retained immutable result identities, independently of
// the latest-100 jobs screen. Each page projects at most one result so an
// unrelated large scan cannot make a global read aggregate unbounded evidence.
func (q *Queue) Catalogue(ctx context.Context, owner string, in CatalogueQuery) (CataloguePage, error) {
	if len(in.Repository) > 128 || len(in.Cursor) > 2048 || len(in.Since) > 64 || len(in.Until) > 64 {
		return CataloguePage{}, ErrInput
	}
	query, e := normalizeFindingQuery(FindingQuery{Category: in.Category, Severity: in.Severity, Limit: in.Limit})
	if e != nil {
		return CataloguePage{}, e
	}
	in.Limit = query.Limit
	var since, until time.Time
	for _, item := range []struct {
		raw   *string
		stamp *time.Time
	}{{&in.Since, &since}, {&in.Until, &until}} {
		if *item.raw != "" {
			parsed, e := time.Parse(time.RFC3339Nano, *item.raw)
			if e != nil {
				return CataloguePage{}, ErrInput
			}
			*item.stamp = parsed.UTC()
			*item.raw = parsed.UTC().Format(time.RFC3339Nano)
		}
	}
	if in.Since != "" && in.Until != "" && !until.After(since) {
		return CataloguePage{}, ErrInput
	}

	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return CataloguePage{}, e
	}
	defer tx.Rollback()
	if in.Repository != "" {
		var id string
		if e = tx.QueryRowContext(ctx, "SELECT id FROM repositories WHERE owner=? AND id=?", owner, in.Repository).Scan(&id); e != nil {
			return CataloguePage{}, e
		}
	}
	sqlText := "SELECT j.id,r.job,r.owner,r.digest,r.request_digest,j.request_digest,r.created_at FROM scanner_jobs j LEFT JOIN scanner_results r ON r.job=j.id WHERE j.owner=?"
	args := []any{owner}
	if in.Repository != "" {
		sqlText += " AND j.repository=?"
		args = append(args, in.Repository)
	}
	// The roster covers every retained job (the queue budget), so the catalogue
	// keeps working as history grows.
	sqlText += fmt.Sprintf(" ORDER BY coalesce(r.created_at,j.created_at) DESC,j.id DESC LIMIT %d", RetainedJobBudget+1)
	rows, e := tx.QueryContext(ctx, sqlText, args...)
	if e != nil {
		return CataloguePage{}, e
	}
	roster := []catalogueRow{}
	unavailable, total := 0, 0
	for rows.Next() {
		var job, request string
		var resultJob, resultOwner, digest, resultRequest, created sql.NullString
		if e = rows.Scan(&job, &resultJob, &resultOwner, &digest, &resultRequest, &request, &created); e != nil {
			rows.Close()
			return CataloguePage{}, e
		}
		total++
		if total > RetainedJobBudget {
			rows.Close()
			return CataloguePage{}, ErrFindingBudget
		}
		if !resultJob.Valid {
			unavailable++
			continue
		}
		if resultJob.String != job || !resultOwner.Valid || resultOwner.String != owner || !digest.Valid || !digestPattern.MatchString(digest.String) || !resultRequest.Valid || resultRequest.String != request {
			rows.Close()
			return CataloguePage{}, ErrConflict
		}
		stamp, e := time.Parse(time.RFC3339Nano, created.String)
		if !created.Valid || e != nil {
			rows.Close()
			return CataloguePage{}, ErrConflict
		}
		if in.Since != "" && stamp.Before(since) || in.Until != "" && !stamp.Before(until) {
			continue
		}
		roster = append(roster, catalogueRow{Job: job, Digest: digest.String, Created: created.String, stamp: stamp})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return CataloguePage{}, e
	}
	sort.Slice(roster, func(i, j int) bool {
		if !roster[i].stamp.Equal(roster[j].stamp) {
			return roster[i].stamp.After(roster[j].stamp)
		}
		return roster[i].Job > roster[j].Job
	})
	set := domain.Digest(struct {
		Owner   string         `json:"owner_id"`
		Query   CatalogueQuery `json:"query"`
		Results []catalogueRow `json:"results"`
	}{owner, in, roster})
	cursor, e := decodeCatalogueCursor(in.Cursor, set, len(roster))
	if e != nil {
		return CataloguePage{}, e
	}
	out := CataloguePage{Schema: "1.0", Owner: owner, Scope: "retained_static_observations", Set: set, Results: len(roster), Unavailable: unavailable, Index: cursor.Index, Next: ""}
	if len(roster) == 0 {
		if e = ctx.Err(); e != nil {
			return CataloguePage{}, e
		}
		return out, nil
	}
	selected := roster[cursor.Index]
	query.Cursor = cursor.Inner
	page, result, e := q.findingsWithResultTx(ctx, tx, owner, selected.Job, query, "")
	if e != nil {
		return CataloguePage{}, e
	}
	if result.Digest != selected.Digest || page.Result != selected.Digest {
		return CataloguePage{}, ErrConflict
	}
	out.Result = &result
	out.Findings = &page
	if page.Next != "" {
		cursor.Inner = page.Next
		out.Next = encodeCatalogueCursor(cursor)
	} else if cursor.Index+1 < len(roster) {
		cursor.Index++
		cursor.Inner = ""
		out.Next = encodeCatalogueCursor(cursor)
	}
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > 120<<10 {
		return CataloguePage{}, ErrFindingBudget
	}
	if e = ctx.Err(); e != nil {
		return CataloguePage{}, e
	}
	return out, nil
}
