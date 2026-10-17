// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func appendCatalogueError(t *testing.T, q *Queue, l Lease, key string, step ...time.Duration) {
	t.Helper()
	// Test-only fixture reuse: production has no cleanup-release path.
	if _, e := q.S.DB.Exec("DELETE FROM scanner_dispatch"); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Enqueue(l.Job.Owner, key, l.Job.Input); e != nil {
		t.Fatal(e)
	}
	next, e := q.Claim("trusted-worker", l.Job.Owner)
	if e != nil {
		t.Fatal(e)
	}
	var raw string
	if e = q.S.DB.QueryRow("SELECT document FROM scanner_receipts WHERE job=?", l.Job.ID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var previous ReceiptDocument
	if e = json.Unmarshal([]byte(raw), &previous); e != nil {
		t.Fatal(e)
	}
	ex := previous.Execution
	ex.Status = "tool_error"
	ex.Result = scanevidence.Result{Status: "tool_error", Findings: []scanevidence.Finding{}, Diagnostics: []scanevidence.Diagnostic{}}
	ex.Exit = -1
	ex.Container = ""
	ex.GuardDigest = ""
	ex.DurationLimit = 0
	ex.Duration = 0
	ex.Cleanup = "unconfirmed"
	ex.Started = q.now().UTC().Format(time.RFC3339Nano)
	duration := time.Second
	if len(step) > 0 {
		duration = step[0]
	}
	now := q.now().Add(duration)
	q.Now = func() time.Time { return now }
	if _, e = q.RecordReceipt(next, ex); e != nil {
		t.Fatal(e)
	}
	if _, e = q.Finalize(next); e != nil {
		t.Fatal(e)
	}
}
func TestCatalogueWalksEveryOwnedResultAndFindingWithoutPromotingClaims(t *testing.T) {
	q, l, result := findingResult(t, 5)
	ctx := context.Background()
	// Include unavailable work and a terminal tool failure; neither is clean evidence.
	if _, e := q.Enqueue(l.Job.Owner, "catalogue-unavailable", l.Job.Input); e != nil {
		t.Fatal(e)
	}
	first, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	if first.Results != 1 || first.Unavailable != 1 || first.Result.Digest != result.Digest || first.Findings.ToolClaims != 5 || len(first.Findings.Items) != 2 || first.Next == "" {
		t.Fatal(first)
	}
	seen := map[string]bool{}
	query := CatalogueQuery{Limit: 2}
	pages := 0
	for {
		out, e := q.Catalogue(ctx, l.Job.Owner, query)
		if e != nil {
			t.Fatal(e)
		}
		pages++
		if out.Set != first.Set || out.Scope != "retained_static_observations" || out.Result.Digest != result.Digest {
			t.Fatal(out)
		}
		for _, entry := range out.Findings.Items {
			if seen[entry.ID] || entry.Finding.Tier != "T0" || entry.Finding.Status != "suspected" {
				t.Fatal("duplicate/promoted claim")
			}
			seen[entry.ID] = true
		}
		if out.Next == "" {
			break
		}
		query.Cursor = out.Next
		if pages > 5 {
			t.Fatal("pagination loop")
		}
	}
	if len(seen) != 5 || pages != 3 {
		t.Fatal(len(seen), pages)
	}
	t.Logf("CATALOGUE_FIRST %s", mustTriageJSON(first))
	old := first.Next
	appendCatalogueError(t, q, l, "catalogue-new-result")
	if _, e = q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Limit: 2, Cursor: old}); !errors.Is(e, ErrCatalogueChanged) {
		t.Fatal("mixed changed result set", e)
	}
	all := []CataloguePage{}
	query = CatalogueQuery{Limit: 2}
	for {
		out, e := q.Catalogue(ctx, l.Job.Owner, query)
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, out)
		if out.Next == "" {
			break
		}
		query.Cursor = out.Next
		if len(all) > 6 {
			t.Fatal("loop")
		}
	}
	if len(all) != 4 || all[0].Results != 2 {
		t.Fatal(len(all))
	}
	errorSeen := false
	for _, page := range all {
		if page.Findings.ToolError {
			errorSeen = true
			if page.Findings.Status != "tool_error" || len(page.Findings.Items) != 0 {
				t.Fatal("failure hidden")
			}
		}
	}
	if !errorSeen {
		t.Fatal("error result missing")
	}
	var held string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&held)
	if held != "cleanup_required" {
		t.Fatal("read released cleanup")
	}
}
func TestCatalogueFiltersAndCursorsAreOwnerAndQueryBound(t *testing.T) {
	q, l, _ := findingResult(t, 3)
	ctx := context.Background()
	first, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Limit: 1})
	if e != nil {
		t.Fatal(e)
	}
	other, e := q.Catalogue(ctx, "owner-b", CatalogueQuery{})
	if e != nil || other.Results != 0 || other.Unavailable != 0 || other.Result != nil || other.Findings != nil || other.Next != "" {
		t.Fatal("cross owner data", other, e)
	}
	if _, e = q.Catalogue(ctx, "owner-b", CatalogueQuery{Limit: 1, Cursor: first.Next}); !errors.Is(e, ErrCatalogueChanged) {
		t.Fatal("other-owner cursor accepted", e)
	}
	if _, e = q.Catalogue(ctx, "owner-b", CatalogueQuery{Repository: l.Job.Input.Repository}); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross owner repository", e)
	}
	for _, changed := range []CatalogueQuery{{Limit: 2, Cursor: first.Next}, {Limit: 1, Severity: "low", Cursor: first.Next}, {Limit: 1, Repository: l.Job.Input.Repository, Cursor: first.Next}} {
		if _, e = q.Catalogue(ctx, l.Job.Owner, changed); !errors.Is(e, ErrCatalogueChanged) {
			t.Fatal("changed query", e)
		}
	}
	filtered, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Repository: l.Job.Input.Repository, Severity: "low"})
	if e != nil || filtered.Results != 1 || filtered.Findings.Matching != 0 || len(filtered.Findings.Items) != 0 || filtered.Findings.ToolClaims != 3 {
		t.Fatal(filtered, e)
	}
	for _, bad := range []CatalogueQuery{{Limit: 21}, {Category: "runtime_exploit"}, {Severity: "safe"}, {Repository: strings.Repeat("x", 129)}, {Cursor: strings.Repeat("a", 2049)}, {Cursor: "not-base64"}} {
		if _, e = q.Catalogue(ctx, l.Job.Owner, bad); !errors.Is(e, ErrInput) {
			t.Fatal("invalid filters", e)
		}
	}
	cursor := catalogueCursor{Schema: "1.0", Set: first.Set, Index: 1}
	if _, e = q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Limit: 1, Cursor: encodeCatalogueCursor(cursor)}); !errors.Is(e, ErrInput) {
		t.Fatal("out of range", e)
	}
	if _, e = q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Limit: 1, Cursor: base64.RawURLEncoding.EncodeToString([]byte(`{"schema_version":"1.0","extra":true}`))}); !errors.Is(e, ErrInput) {
		t.Fatal("unknown cursor", e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = q.Catalogue(cancelled, l.Job.Owner, CatalogueQuery{}); e == nil {
		t.Fatal("cancelled read succeeded")
	}
}
func TestCatalogueDoesNotLimitHistoryToLatestHundredJobs(t *testing.T) {
	q, l, result := findingResult(t, 1)
	ctx := context.Background()
	now := q.now().Add(time.Second)
	q.Now = func() time.Time { return now }
	for i := 0; i < 105; i++ {
		j, e := q.Enqueue(l.Job.Owner, fmt.Sprintf("catalogue-history-%d", i), l.Job.Input)
		if e != nil {
			t.Fatal(i, e)
		}
		if e = q.Cancel(l.Job.Owner, j.ID); e != nil {
			t.Fatal(e)
		}
	}
	jobs, e := q.List(l.Job.Owner)
	if e != nil || len(jobs) != 100 {
		t.Fatal(e)
	}
	for _, j := range jobs {
		if j.ID == l.Job.ID {
			t.Fatal("fixture not beyond latest 100")
		}
	}
	out, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{})
	if e != nil || out.Results != 1 || out.Unavailable != 105 || out.Result.Digest != result.Digest {
		t.Fatal(out, e)
	}
}
func TestCatalogueRejectsCorruptIndexAndSourceEvidence(t *testing.T) {
	for _, kind := range []string{"owner", "request", "digest", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			q, l, _ := findingResult(t, 1)
			q.S.DB.Exec("DROP TRIGGER scanner_results_no_update")
			q.S.DB.Exec("DROP TRIGGER scanner_receipts_no_update")
			switch kind {
			case "owner":
				q.S.DB.Exec("UPDATE scanner_results SET owner='owner-b'")
			case "request":
				q.S.DB.Exec("UPDATE scanner_results SET request_digest='bad'")
			case "digest":
				q.S.DB.Exec("UPDATE scanner_results SET digest=?", domain.Hash([]byte("changed")))
			case "receipt":
				q.S.DB.Exec("UPDATE scanner_receipts SET document='{}'")
			}
			if _, e := q.Catalogue(context.Background(), l.Job.Owner, CatalogueQuery{}); !errors.Is(e, ErrConflict) {
				t.Fatal("corrupt evidence listed", e)
			}
		})
	}
}

func TestCatalogueTimeFiltersAndFractionalOrdering(t *testing.T) {
	q, l, ex, _ := completedReceipt(t, "completed")
	ctx := context.Background()
	now := q.now().Truncate(time.Second).Add(2 * time.Second)
	q.Now = func() time.Time { return now }
	if _, e := q.RecordReceipt(l, ex); e != nil {
		t.Fatal(e)
	}
	initial, e := q.Finalize(l)
	if e != nil {
		t.Fatal(e)
	}
	base := q.now()
	appendCatalogueError(t, q, l, "catalogue-fractional", time.Nanosecond)
	out, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{})
	if e != nil || out.Results != 2 || !out.Findings.ToolError {
		t.Fatal("fractional result chronology", e)
	}
	filtered, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Since: base.Format(time.RFC3339Nano), Until: base.Add(time.Nanosecond).Format(time.RFC3339Nano)})
	if e != nil || filtered.Results != 1 || filtered.Result.Digest != initial.Digest {
		t.Fatal("inclusive since / exclusive until", filtered, e)
	}
	offset, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Since: base.In(time.FixedZone("offset", 8*3600)).Format(time.RFC3339Nano), Until: base.Add(time.Nanosecond).Format(time.RFC3339Nano)})
	if e != nil || offset.Set != filtered.Set {
		t.Fatal("equivalent offset times changed query identity", e)
	}
	zero, e := q.Catalogue(ctx, l.Job.Owner, CatalogueQuery{Until: "0001-01-01T00:00:00Z"})
	if e != nil || zero.Results != 0 {
		t.Fatal("zero timestamp treated as absent", e)
	}
	for _, bad := range []CatalogueQuery{{Since: "not-time"}, {Until: "tomorrow"}, {Since: base.Format(time.RFC3339Nano), Until: base.Format(time.RFC3339Nano)}, {Since: strings.Repeat("x", 65)}} {
		if _, e := q.Catalogue(ctx, l.Job.Owner, bad); !errors.Is(e, ErrInput) {
			t.Fatal("invalid time filter", e)
		}
	}
}

func TestCatalogueByteBudgetPreservesAllProvenanceAndContinuation(t *testing.T) {
	q, l, _ := findingResult(t, 20, true)
	ctx := context.Background()
	query := CatalogueQuery{Limit: 20}
	seen := map[string]bool{}
	pages := 0
	for {
		out, e := q.Catalogue(ctx, l.Job.Owner, query)
		if e != nil {
			t.Fatal(e)
		}
		pages++
		raw, _ := json.Marshal(out)
		if len(raw) > 120<<10 || len(out.Findings.Items) == 0 {
			t.Fatal("oversized or empty projection", len(raw))
		}
		for _, entry := range out.Findings.Items {
			if len(entry.Finding.Provenance) != 16 || seen[entry.ID] {
				t.Fatal("lost or repeated source evidence")
			}
			seen[entry.ID] = true
		}
		if out.Next == "" {
			break
		}
		query.Cursor = out.Next
		if pages > 20 {
			t.Fatal("cursor loop")
		}
	}
	if pages < 2 || len(seen) != 20 {
		t.Fatal("byte split lost records", pages, len(seen))
	}
}
