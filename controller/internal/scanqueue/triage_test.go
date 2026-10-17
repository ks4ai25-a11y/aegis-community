// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func triageFixture(t *testing.T) (*Queue, Lease, FindingTriageInput) {
	t.Helper()
	q, l, r := findingResult(t, 2)
	page, e := q.Findings(context.Background(), l.Job.Owner, l.Job.ID, FindingQuery{Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	return q, l, FindingTriageInput{Schema: "1.0", Record: page.Items[0].ID, Result: r.Digest, State: "unverified", Rationale: "Requires ownership context"}
}
func TestTriageAppendsAssessmentWithoutChangingEvidenceOrAdmission(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	baseline, e := q.Result(l.Job.Owner, l.Job.ID)
	if e != nil {
		t.Fatal(e)
	}
	initial, e := q.FindingTriage(ctx, l.Job.Owner, l.Job.ID, in.Record)
	if e != nil || initial.Document.Revision != 0 || initial.Document.State != "suspected" || initial.Document.Rationale != "" || initial.Document.Updated != "" {
		t.Fatal(initial, e)
	}
	first, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-first-key", in)
	if e != nil || first.Document.Revision != 1 || first.Document.Previous != "" {
		t.Fatal(first, e)
	}
	secondInput := in
	secondInput.Expected = 1
	secondInput.State = "accepted_risk"
	secondInput.Rationale = "Accepted pending application review"
	second, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-second-key", secondInput)
	if e != nil || second.Document.Revision != 2 || second.Document.Previous != first.Digest {
		t.Fatal(second, e)
	}
	replay, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-first-key", in)
	if e != nil || replay != first {
		t.Fatal("lost response replay changed", replay, e)
	}
	current, e := q.FindingTriage(ctx, l.Job.Owner, l.Job.ID, in.Record)
	if e != nil || current != second {
		t.Fatal(current, e)
	}
	after, e := q.Result(l.Job.Owner, l.Job.ID)
	if e != nil || after.Digest != baseline.Digest {
		t.Fatal("triage changed source result", e)
	}
	page, e := q.Findings(ctx, l.Job.Owner, l.Job.ID, FindingQuery{})
	if e != nil || page.ToolClaims != 2 || page.Distinct != 2 {
		t.Fatal(page, e)
	}
	for _, entry := range page.Items {
		if entry.Finding.Tier != "T0" || entry.Finding.Status != "suspected" || entry.Finding.Confidence != "low" {
			t.Fatal("assessment promoted evidence")
		}
	}
	var admission string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&admission)
	if admission != "cleanup_required" {
		t.Fatal("triage released admission")
	}
	var count int
	q.S.DB.QueryRow("SELECT count(*) FROM finding_triage").Scan(&count)
	if count != 2 {
		t.Fatal("replay duplicated history")
	}
	var raw string
	q.S.DB.QueryRow("SELECT group_concat(document) FROM audit WHERE document LIKE '%finding.triage%'").Scan(&raw)
	if strings.Contains(raw, in.Rationale) || strings.Contains(raw, secondInput.Rationale) {
		t.Fatal("rationale copied into audit")
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	t.Logf("FINDING_TRIAGE_INITIAL %s", mustTriageJSON(initial))
	t.Logf("FINDING_TRIAGE_RECORDED %s", mustTriageJSON(second))
}
func mustTriageJSON(value any) string { b, _ := json.Marshal(value); return string(b) }
func TestTriageRefusesCrossOwnerResultRecordAndChangedOrStaleRequests(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	if _, e := q.SetFindingTriage(ctx, "owner-b", l.Job.ID, "triage-isolation", in); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross owner", e)
	}
	if _, e := q.SetFindingTriage(ctx, l.Job.Owner, "unknown-job", "triage-isolation", in); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("unknown job", e)
	}
	for _, kind := range []string{"result", "record"} {
		changed := in
		if kind == "result" {
			changed.Result = domain.Hash([]byte("other result"))
		} else {
			changed.Record = domain.Hash([]byte("other record"))
		}
		if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-isolation", changed); e == nil {
			t.Fatal(kind, "accepted")
		}
	}
	first, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-isolation", in)
	if e != nil {
		t.Fatal(e)
	}
	changed := in
	changed.State = "false_positive"
	if _, e = q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-isolation", changed); !errors.Is(e, ErrConflict) {
		t.Fatal("changed retry", e)
	}
	if _, e = q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-stale-key", in); !errors.Is(e, ErrConflict) {
		t.Fatal("stale revision", e)
	}
	current, e := q.FindingTriage(ctx, l.Job.Owner, l.Job.ID, in.Record)
	if e != nil || current != first {
		t.Fatal(current, e)
	}
	for _, state := range []string{"corroborated", "reproduced", "fixed_or_mitigated", "monitored", "verified", ""} {
		bad := in
		bad.State = state
		if _, e = q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-invalid-key", bad); !errors.Is(e, ErrInput) {
			t.Fatal(state, e)
		}
	}
	for _, reason := range []string{"short"[:4], strings.Repeat("x", 513), " leading rationale", "rationale\nnew line", string([]byte{255, 255, 255, 255, 255})} {
		bad := in
		bad.Rationale = reason
		if _, e = q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-invalid-key", bad); !errors.Is(e, ErrInput) {
			t.Fatal("unsafe rationale accepted", e)
		}
	}
	if _, e = q.FindingTriage(ctx, "owner-b", l.Job.ID, in.Record); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = q.SetFindingTriage(cancelled, l.Job.Owner, l.Job.ID, "triage-cancelled", in); e == nil {
		t.Fatal("cancelled write succeeded")
	}
}
func TestTriageConcurrentRevisionHasOneWinner(t *testing.T) {
	q, l, in := triageFixture(t)
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := q.SetFindingTriage(context.Background(), l.Job.Owner, l.Job.ID, fmt.Sprintf("triage-concurrent-%d", i), in)
			out <- e
		}(i)
	}
	wg.Wait()
	close(out)
	success, conflict := 0, 0
	for e := range out {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal(success, conflict)
	}
}
func TestTriageHistoryIsImmutableAndAuditFailureRollsBack(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	if _, e := q.S.DB.Exec("CREATE TRIGGER refuse_triage_audit BEFORE INSERT ON audit WHEN NEW.document LIKE '%finding.triage%' BEGIN SELECT RAISE(ABORT,'test audit failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-audit-key", in); e == nil {
		t.Fatal("audit failure accepted")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM finding_triage").Scan(&n)
	if n != 0 {
		t.Fatal("orphan assessment")
	}
	q.S.DB.Exec("DROP TRIGGER refuse_triage_audit")
	if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-audit-key", in); e != nil {
		t.Fatal(e)
	}
	for _, sql := range []string{"UPDATE finding_triage SET document='{}'", "DELETE FROM finding_triage"} {
		if _, e := q.S.DB.Exec(sql); e == nil {
			t.Fatal("mutable history")
		}
	}
	q.S.DB.Exec("DROP TRIGGER finding_triage_no_update")
	q.S.DB.Exec("UPDATE finding_triage SET request_digest='tampered'")
	if _, e := q.Findings(ctx, l.Job.Owner, l.Job.ID, FindingQuery{}); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupt review projected", e)
	}
	if _, e := q.FindingTriage(ctx, l.Job.Owner, l.Job.ID, in.Record); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupt chain read", e)
	}
	if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-audit-key", in); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupt replay", e)
	}
}
func TestTriageHistoryAndGlobalBudgetsAreBounded(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		in.Expected = i
		if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, fmt.Sprintf("triage-revision-%d", i), in); e != nil {
			t.Fatal(i, e)
		}
	}
	in.Expected = 50
	if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-over-budget", in); !errors.Is(e, ErrInput) {
		t.Fatal("revision budget", e)
	}
	for _, kind := range []string{"rows", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			q, l, in := triageFixture(t)
			if kind == "rows" {
				_, e := q.S.DB.Exec("WITH RECURSIVE nums(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM nums WHERE n<20000) INSERT INTO finding_triage SELECT ?, 'synthetic-'||n, ?, ?, 1, 'budget-'||n, 'unused', 'budget-digest-'||n, '{}', 'unused' FROM nums", l.Job.ID, l.Job.Owner, in.Result)
				if e != nil {
					t.Fatal(e)
				}
			} else {
				_, e := q.S.DB.Exec("INSERT INTO finding_triage VALUES(?,?,?,?,1,'budget-bytes','unused','budget-digest',?,'unused')", l.Job.ID, "unrelated-record", l.Job.Owner, in.Result, strings.Repeat("x", 16<<20))
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-global-budget", in); !errors.Is(e, ErrFull) {
				t.Fatal(kind, e)
			}
		})
	}
}
func TestTriageCannotWriteAgainstMissingOrCorruptEvidence(t *testing.T) {
	q, l, in := triageFixture(t)
	q.S.DB.Exec("DROP TRIGGER scanner_receipts_no_update")
	q.S.DB.Exec("UPDATE scanner_receipts SET document='{}'")
	if _, e := q.SetFindingTriage(context.Background(), l.Job.Owner, l.Job.ID, "triage-corrupt-evidence", in); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM finding_triage").Scan(&n)
	if n != 0 {
		t.Fatal("triaged corrupt evidence")
	}
}

func TestTriageSurvivesRestartWithoutInventingVerifiedEvidence(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	first, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-restart-key", in)
	if e != nil {
		t.Fatal(e)
	}
	path := q.S.Path
	q.S.DB.Close()
	reopened, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	q.S = reopened
	latest, e := q.FindingTriage(ctx, l.Job.Owner, l.Job.ID, in.Record)
	if e != nil || latest != first {
		t.Fatal(latest, e)
	}
	replay, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, "triage-restart-key", in)
	if e != nil || replay != first {
		t.Fatal(replay, e)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
