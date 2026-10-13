// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func receiptFixture(t *testing.T, tools ...string) (*Queue, Lease, scanevidence.Execution, string) {
	t.Helper()
	q, in, path := fixture(t)
	if len(tools) > 0 {
		in.Tools = append([]string{}, tools...)
	}
	q.Pins = map[string]Pin{"bandit": {"1.9.4", domain.Hash([]byte("fixture-image"))}}
	l := enqueueClaim(t, q, in)
	now := q.now()
	q.Now = func() time.Time { return now.Add(time.Second) }
	manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range manifest.Files {
		manifest.Bytes += f.Size
	}
	manifest.Digest = domain.Digest(manifest)
	invocation, _ := scanevidence.BuildInvocation("bandit")
	r := scanevidence.Execution{Schema: "1.0", Parser: scanevidence.ParserVersion, Tool: "bandit", Version: q.Pins["bandit"].Version, Image: q.Pins["bandit"].Image, LockDigest: q.LockDigest, Profile: "repo_offline-network-none-v1", Invocation: invocation, Snapshot: manifest, Started: now.Format(time.RFC3339Nano), Exit: -1, Status: "tool_error", Cleanup: "unconfirmed", Result: scanevidence.Result{Status: "tool_error", Findings: []scanevidence.Finding{}, Diagnostics: []scanevidence.Diagnostic{}}, Limitations: []string{"private arbitrary message"}}
	return q, l, r, path
}
func TestReceiptLedgerPersistsImmutableReplayAcrossRestart(t *testing.T) {
	q, l, r, path := receiptFixture(t)
	got, e := q.RecordReceipt(l, r)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := q.Receipts(l.Job.Owner, l.Job.ID)
	if e != nil || len(rows) != 1 || rows[0].Digest != got.Digest {
		t.Fatal("owner read lost receipt", e)
	}
	if got.Document.Execution.Limitations[0] == r.Limitations[0] {
		t.Fatal("untrusted free text persisted")
	}
	j, e := q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || j.State != "running" {
		t.Fatal("receipt fabricated completion")
	}
	var state string
	if e = q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state); e != nil || state != "active" {
		t.Fatal("receipt released admission")
	}
	for _, sqlText := range []string{"UPDATE scanner_receipts SET document='{}'", "DELETE FROM scanner_receipts"} {
		if _, e = q.S.DB.Exec(sqlText); e == nil {
			t.Fatal("immutable ledger allowed mutation")
		}
	}
	if _, e = q.Receipts("owner-b", l.Job.ID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner receipt read accepted")
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	q.S.DB.Close()
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	later := q.now().Add(20 * time.Second)
	reopened := &Queue{S: s, LockDigest: domain.Hash([]byte("later operator lock")), Now: func() time.Time { return later }}
	replay, e := reopened.RecordReceipt(l, r)
	if e != nil || replay.Digest != got.Digest {
		t.Fatal("immutable replay failed after restart/expiry/pin rotation", e)
	}
	var count int
	if e = s.DB.QueryRow("SELECT count(*) FROM audit WHERE document LIKE '%scanner.receipt%'").Scan(&count); e != nil || count != 1 {
		t.Fatal("replay duplicated audit")
	}
	r.Started = nowLater(l).Format(time.RFC3339Nano)
	if _, e = reopened.RecordReceipt(l, r); !errors.Is(e, ErrConflict) {
		t.Fatal("conflicting replay changed receipt", e)
	}
}
func nowLater(l Lease) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, l.Job.Created)
	return t.Add(500 * time.Millisecond)
}
func TestReceiptLedgerRefusesIdentityPinsAndExpiredNewWrites(t *testing.T) {
	for _, kind := range []string{"owner", "request", "capability", "pin", "tool", "snapshot", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			q, l, r, _ := receiptFixture(t)
			switch kind {
			case "owner":
				l.Job.Owner = "owner-b"
			case "request":
				l.Job.RequestDigest = domain.Hash([]byte("other"))
			case "capability":
				l.Token = "wrong"
			case "pin":
				r.Image = domain.Hash([]byte("other"))
			case "tool":
				r.Tool = "syft"
			case "snapshot":
				r.Snapshot.Digest = domain.Hash([]byte("other"))
			case "expiry":
				later := q.now().Add(20 * time.Second)
				q.Now = func() time.Time { return later }
			}
			if _, e := q.RecordReceipt(l, r); e == nil {
				t.Fatal("invalid receipt accepted")
			}
			var n int
			if e := q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n); e != nil || n != 0 {
				t.Fatal("refusal persisted evidence")
			}
		})
	}
}
func TestReceiptAuditFailureRollsBackEvidence(t *testing.T) {
	q, l, r, _ := receiptFixture(t)
	if _, e := q.S.DB.Exec("CREATE TRIGGER receipt_audit_fail BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture audit unavailable'); END;"); e != nil {
		t.Fatal(e)
	}
	if _, e := q.RecordReceipt(l, r); e == nil {
		t.Fatal("receipt committed without audit")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n)
	if n != 0 {
		t.Fatal("receipt survived audit rollback")
	}
	j, e := q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || j.State != "running" {
		t.Fatal("audit failure changed job")
	}
}
func TestReceiptLedgerBoundsTotalBytesBeforeInsert(t *testing.T) {
	q, l, r, _ := receiptFixture(t)
	// Deliberately corrupt host-side fixture state fills the ledger byte budget.
	// The writer must refuse new evidence without loading/exporting that document.
	if _, e := q.S.DB.Exec("INSERT INTO scanner_receipts VALUES(?,?,?,?,?,zeroblob(?),?)", l.Job.ID, "semgrep_ce", l.Job.Owner, l.Job.RequestDigest, "fixture-budget-sentinel", maxLedgerBytes, q.now().UTC().Format(time.RFC3339Nano)); e != nil {
		t.Fatal(e)
	}
	if _, e := q.RecordReceipt(l, r); !errors.Is(e, ErrFull) {
		t.Fatal("global receipt byte cap ignored", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n)
	if n != 1 {
		t.Fatal("budget refusal partially wrote receipt")
	}
}
func TestReceiptReadChecksDigestAndRelationalIdentity(t *testing.T) {
	q, l, r, _ := receiptFixture(t)
	got, e := q.RecordReceipt(l, r)
	if e != nil {
		t.Fatal(e)
	}
	var doc string
	q.S.DB.QueryRow("SELECT document FROM scanner_receipts").Scan(&doc)
	if _, e = decodeReceipt(doc, got.Digest, "owner-b", l.Job.ID, l.Job.RequestDigest, r.Tool, got.Created); !errors.Is(e, ErrConflict) {
		t.Fatal("cross-owner stored identity accepted")
	}
	if _, e = decodeReceipt(doc+" ", got.Digest, l.Job.Owner, l.Job.ID, l.Job.RequestDigest, r.Tool, got.Created); !errors.Is(e, ErrConflict) {
		t.Fatal("stored bytes changed without digest refusal")
	}
}
