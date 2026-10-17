// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func findingResult(t *testing.T, n int, wide ...bool) (*Queue, Lease, SuiteResult) {
	t.Helper()
	q, l, r, _ := completedReceipt(t, "completed")
	r.Exit = 1
	rule := "B307"
	if len(wide) > 0 && wide[0] {
		rule = "B" + strings.Repeat("x", 159)
	}
	for i := 0; i < n; i++ {
		r.Result.Findings = append(r.Result.Findings, scanevidence.Finding{Schema: "1.0", ID: domain.Digest([]string{l.Job.Input.App, l.Job.Input.Repository, "static_pattern", r.Tool, rule, l.Map.Files[0].Path, fmt.Sprint(i + 1)}), App: l.Job.Input.App, Repository: l.Job.Input.Repository, Category: "static_pattern", Summary: "untrusted original text", Status: "suspected", Severity: "high", Confidence: "low", Tier: "T0", Path: l.Map.Files[0].Path, Line: i + 1, Created: r.Started, Provenance: []scanevidence.Source{{Tool: r.Tool, Version: r.Version, ImageDigest: r.Image, Parser: r.Parser, InputDigest: r.Snapshot.Digest, Rule: rule, Severity: "high"}}})

		if len(wide) > 0 && wide[0] {
			last := &r.Result.Findings[len(r.Result.Findings)-1]
			for len(last.Provenance) < 16 {
				last.Provenance = append(last.Provenance, last.Provenance[0])
			}
		}
	}
	if _, e := q.RecordReceipt(l, r); e != nil {
		t.Fatal(e)
	}
	out, e := q.Finalize(l)
	if e != nil {
		t.Fatal(e)
	}
	return q, l, out
}
func TestFindingPagesRetainIdentityProvenanceAndStableSeek(t *testing.T) {
	q, l, result := findingResult(t, 5)
	query := FindingQuery{Limit: 2}
	seen := map[string]bool{}
	total := 0
	for {
		page, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, query)
		if e != nil {
			t.Fatal(e)
		}
		if page.Result != result.Digest || page.Snapshot != result.Document.Snapshot || page.ToolClaims != 5 || page.Distinct != 5 || page.Matching != 5 {
			t.Fatal(page)
		}
		b, _ := json.Marshal(page)
		if len(b) > 96<<10 || strings.Contains(string(b), "untrusted original text") {
			t.Fatal("unsafe finding page")
		}
		for _, entry := range page.Items {
			f := entry.Finding
			if seen[entry.ID] || f.Status != "suspected" || f.Tier != "T0" || f.Confidence != "low" || len(entry.Receipts) != 1 || entry.Receipts[0] != result.Document.Tools[0].Receipt {
				t.Fatal(entry)
			}
			seen[entry.ID] = true
			total++
		}
		if page.Next == "" {
			break
		}
		query.Cursor = page.Next
	}
	if total != 5 {
		t.Fatal(total)
	}
	first, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	changed := FindingQuery{Limit: 1, Cursor: first.Next}
	if _, e = q.Findings(context.Background(), l.Job.Owner, l.Job.ID, changed); !errors.Is(e, ErrInput) {
		t.Fatal("cursor crossed page definition", e)
	}
	changed = FindingQuery{Limit: 2, Cursor: first.Next, Severity: "low"}
	if _, e = q.Findings(context.Background(), l.Job.Owner, l.Job.ID, changed); !errors.Is(e, ErrInput) {
		t.Fatal("cursor crossed filters", e)
	}
	if _, e = q.Findings(context.Background(), "owner-b", l.Job.ID, FindingQuery{Cursor: first.Next}); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner findings", e)
	}
	filtered, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{Severity: "low"})
	if e != nil || len(filtered.Items) != 0 || filtered.Distinct != 5 || filtered.Matching != 0 || filtered.Status != "completed" {
		t.Fatal(filtered, e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal("read released admission")
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestFindingReadRefusesUnavailableCorruptAndCancelledContext(t *testing.T) {
	q, l, _, _ := completedReceipt(t, "completed")
	if _, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{}); !errors.Is(e, ErrResultUnavailable) {
		t.Fatal("missing result became empty findings", e)
	}
	q, l, _ = findingResult(t, 1)
	for _, query := range []FindingQuery{{Limit: 21}, {Category: "runtime_waf"}, {Severity: "verified"}, {Cursor: strings.Repeat("a", 513)}, {Cursor: "not-json"}} {
		if _, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, query); !errors.Is(e, ErrInput) {
			t.Fatal(query, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := q.Findings(ctx, l.Job.Owner, l.Job.ID, FindingQuery{}); e == nil {
		t.Fatal("cancelled read succeeded")
	}
	q.S.DB.Exec("DROP TRIGGER scanner_receipts_no_update")
	q.S.DB.Exec("UPDATE scanner_receipts SET document='{}'")
	if _, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{}); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupt receipt became empty findings", e)
	}
}

func TestFindingPageByteBudgetAdvancesWithoutDroppingProvenance(t *testing.T) {
	q, l, _ := findingResult(t, 20, true)
	page, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{})
	if e != nil || len(page.Items) == 0 || len(page.Items) >= 20 || page.Next == "" {
		t.Fatal("byte budget did not split page", len(page.Items), e)
	}
	encoded, _ := json.Marshal(page)
	if len(encoded) > 96<<10 {
		t.Fatal("page exceeded response budget", len(encoded))
	}
	total := len(page.Items)
	for _, entry := range page.Items {
		if len(entry.Finding.Provenance) != 16 {
			t.Fatal("provenance truncated")
		}
	}
	for page.Next != "" {
		page, e = q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{Cursor: page.Next})
		if e != nil {
			t.Fatal(e)
		}
		total += len(page.Items)
	}
	if total != 20 {
		t.Fatal("byte bounded paging lost records", total)
	}
}

func TestProjectionIdentityKeepsMissingPURLSourcesSeparate(t *testing.T) {
	f := scanevidence.Finding{ID: domain.Hash([]byte("same incomplete dependency")), Category: "known_vulnerable_dependency", Provenance: []scanevidence.Source{{Tool: "osv_v2", Rule: "CVE-2026-99999", InputDigest: domain.Hash([]byte("input"))}}}

	f.Schema = "1.0"
	f.App = "app_demo"
	f.Repository = "fixture"
	f.Status = "suspected"
	f.Tier = "T0"
	f.Confidence = "low"
	f.Severity = "high"
	f.PackageName = "fixture"
	f.Version = "1.0"
	f.Provenance[0].Version = "1.0"
	f.Provenance[0].ImageDigest = domain.Hash([]byte("fixture image"))
	other := f
	other.Provenance = append([]scanevidence.Source{}, f.Provenance...)
	other.Provenance[0].Tool = "trivy"
	separate, e := scanevidence.Dedupe([]scanevidence.Finding{f, other})
	if e != nil || len(separate) != 2 || findingRecordID("owner-a", separate[0]) == findingRecordID("owner-a", separate[1]) {
		t.Fatal("incomplete coordinates collapsed source records", e)
	}
	first := findingRecordID("owner-a", f)
	f.Provenance[0].Tool = "trivy"
	if first == findingRecordID("owner-a", f) || first == findingRecordID("owner-b", f) {
		t.Fatal("projection crossed source/owner namespace")
	}
	f.Package = "pkg:npm/fixture@1.0"
	first = findingRecordID("owner-a", f)
	f.Provenance[0].Tool = "osv_v2"
	if first != findingRecordID("owner-a", f) {
		t.Fatal("equivalent coordinates lost shared record identity")
	}
}
