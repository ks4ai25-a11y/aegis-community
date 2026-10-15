// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFindingHistoryExportsCompleteBoundChainWithoutWrites(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	initial, e := q.FindingHistory(ctx, l.Job.Owner, l.Job.ID, in.Record, in.Result)
	if e != nil || initial.Document.Count != 0 || len(initial.Document.Items) != 0 || !initial.Document.Complete || initial.Document.Baseline != initial.Document.Head || domain.Digest(initial.Document) != initial.Digest {
		t.Fatal(initial, e)
	}
	saved := []FindingTriageRecord{}
	for i := 0; i < 3; i++ {
		in.Expected = i
		in.Rationale = fmt.Sprintf("Local rationale %d <fixture> & retained", i)
		if i == 1 {
			in.Rationale = "暂缓处置"
		}
		r, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, fmt.Sprintf("history-decision-%d", i), in)
		if e != nil {
			t.Fatal(e)
		}
		saved = append(saved, r)
	}
	var auditBefore, rowsBefore int
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&auditBefore)
	q.S.DB.QueryRow("SELECT count(*) FROM finding_triage").Scan(&rowsBefore)
	history, e := q.FindingHistory(ctx, l.Job.Owner, l.Job.ID, in.Record, in.Result)
	if e != nil {
		t.Fatal(e)
	}
	d := history.Document
	if d.Count != 3 || len(d.Items) != 3 || d.Head != saved[2].Digest || d.Baseline != initial.Document.Baseline || d.Scope != "owner_review_only" || !d.Complete || domain.Digest(d) != history.Digest {
		t.Fatal(history)
	}
	for i, r := range d.Items {
		if r != saved[i] {
			t.Fatal("history changed", i)
		}
		if i > 0 && r.Document.Previous != d.Items[i-1].Digest {
			t.Fatal("broken chain")
		}
	}
	again, e := q.FindingHistory(ctx, l.Job.Owner, l.Job.ID, in.Record, in.Result)
	if e != nil || again.Digest != history.Digest {
		t.Fatal("unstable export", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM audit").Scan(&n)
	if n != auditBefore {
		t.Fatal("read appended audit")
	}
	q.S.DB.QueryRow("SELECT count(*) FROM finding_triage").Scan(&n)
	if n != rowsBefore {
		t.Fatal("read changed ledger")
	}
	source, e := q.Findings(ctx, l.Job.Owner, l.Job.ID, FindingQuery{})
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range source.Items {
		if entry.Finding.Tier != "T0" || entry.Finding.Status != "suspected" {
			t.Fatal("export promoted evidence")
		}
	}
	var admission string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&admission)
	if admission != "cleanup_required" {
		t.Fatal("released admission")
	}
	t.Logf("FINDING_HISTORY_EMPTY %s", mustTriageJSON(initial))
	t.Logf("FINDING_HISTORY_COMPLETE %s", mustTriageJSON(history))
}
func TestFindingHistoryRequiresOwnedExactImmutableEvidence(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	cases := []struct {
		name, owner, job, record, result string
		want                             error
	}{
		{"owner", "other", l.Job.ID, in.Record, in.Result, sql.ErrNoRows}, {"job", l.Job.Owner, "missing", in.Record, in.Result, sql.ErrNoRows}, {"record", l.Job.Owner, l.Job.ID, domain.Hash([]byte("other")), in.Result, sql.ErrNoRows}, {"result", l.Job.Owner, l.Job.ID, in.Record, domain.Hash([]byte("other")), ErrConflict}, {"malformed", l.Job.Owner, l.Job.ID, "bad", in.Result, ErrInput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, e := q.FindingHistory(ctx, c.owner, c.job, c.record, c.result); !errors.Is(e, c.want) {
				t.Fatal(e)
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := q.FindingHistory(cancelled, l.Job.Owner, l.Job.ID, in.Record, in.Result); e == nil {
		t.Fatal("cancelled read succeeded")
	}
	q.S.DB.Exec("DROP TRIGGER scanner_receipts_no_update")
	q.S.DB.Exec("UPDATE scanner_receipts SET document='{}'")
	if _, e := q.FindingHistory(ctx, l.Job.Owner, l.Job.ID, in.Record, in.Result); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupt evidence exported", e)
	}
}
func TestFindingHistoryRefusesBrokenOrIncompleteLedger(t *testing.T) {
	for _, kind := range []string{"document", "request", "missing-first", "gap", "link"} {
		t.Run(kind, func(t *testing.T) {
			q, l, in := triageFixture(t)
			ctx := context.Background()
			for i := 0; i < 2; i++ {
				in.Expected = i
				if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, fmt.Sprintf("history-corruption-%d", i), in); e != nil {
					t.Fatal(e)
				}
			}
			q.S.DB.Exec("DROP TRIGGER finding_triage_no_update")
			q.S.DB.Exec("DROP TRIGGER finding_triage_no_delete")
			switch kind {
			case "document":
				q.S.DB.Exec("UPDATE finding_triage SET document='{}' WHERE revision=1")
			case "request":
				q.S.DB.Exec("UPDATE finding_triage SET request_digest='bad' WHERE revision=1")
			case "missing-first":
				q.S.DB.Exec("DELETE FROM finding_triage WHERE revision=1")
			case "gap":
				q.S.DB.Exec("UPDATE finding_triage SET revision=4 WHERE revision=2")
			case "link":
				var raw string
				if e := q.S.DB.QueryRow("SELECT document FROM finding_triage WHERE revision=2").Scan(&raw); e != nil {
					t.Fatal(e)
				}
				var d FindingTriage
				if e := json.Unmarshal([]byte(raw), &d); e != nil {
					t.Fatal(e)
				}
				d.Previous = domain.Hash([]byte("different predecessor"))
				b, _ := json.Marshal(d)
				if _, e := q.S.DB.Exec("UPDATE finding_triage SET document=?,digest=? WHERE revision=2", string(b), domain.Hash(b)); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := q.FindingHistory(ctx, l.Job.Owner, l.Job.ID, in.Record, in.Result); !errors.Is(e, ErrConflict) {
				t.Fatal("corrupt ledger exported", e)
			}
		})
	}
}
func TestFindingHistoryFullCapacityFitsBoundedClient(t *testing.T) {
	q, l, in := triageFixture(t)
	ctx := context.Background()
	in.Rationale = strings.Repeat("a", 512)
	for i := 0; i < 50; i++ {
		in.Expected = i
		if _, e := q.SetFindingTriage(ctx, l.Job.Owner, l.Job.ID, fmt.Sprintf("history-max-%d", i), in); e != nil {
			t.Fatal(e)
		}
	}
	out, e := q.FindingHistory(ctx, l.Job.Owner, l.Job.ID, in.Record, in.Result)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(out)
	if out.Document.Count != 50 || len(out.Document.Items) != 50 || len(raw) > 120<<10 {
		t.Fatal("full history truncated or oversized", len(raw))
	}
}
