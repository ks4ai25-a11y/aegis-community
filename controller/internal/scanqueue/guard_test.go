// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"encoding/json"
	"errors"
	"testing"
)

func TestGuardSetIsBoundToOriginalDispatchAndCannotRotateLive(t *testing.T) {
	q, in, _ := fixture(t)
	l := enqueueClaim(t, q, in)
	var stored string
	if e := q.S.DB.QueryRow("SELECT guard_set_digest FROM scanner_dispatch").Scan(&stored); e != nil || stored != q.Guards.Digest || l.Guards != q.Guards {
		t.Fatal("dispatch did not bind trusted set", e)
	}
	q.Guards, _ = scanevidence.NewGuardSet(domain.Hash([]byte("different guard")), domain.Hash([]byte("other arm64")))
	if e := q.Guard(l); !errors.Is(e, ErrLease) {
		t.Fatal("rotated set renewed execution", e)
	}
	q, in, _ = fixture(t)
	q.Guards = scanevidence.GuardSet{}
	if _, e := q.Claim("trusted-worker", "owner-a"); !errors.Is(e, ErrInput) {
		t.Fatal("unprovisioned set admitted execution", e)
	}
	_ = in
}
func TestLaunchRejectsWorkerSelectedGuardAndExecutedReceiptMismatch(t *testing.T) {
	for _, kind := range []string{"missing", "other", "architecture", "rotated", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			q, l, _, p := launchFixture(t)
			switch kind {
			case "missing":
				p.Guard = ""
			case "other":
				p.Guard = domain.Hash([]byte("untrusted guard"))
			case "architecture":
				p.Architecture = "arm64"
			case "rotated":
				q.Guards, _ = scanevidence.NewGuardSet(domain.Hash([]byte("new")), domain.Hash([]byte("new arm")))
			case "legacy":
				q.S.DB.Exec("UPDATE scanner_dispatch SET guard_set_digest=''")
			}
			if _, e := q.RegisterLaunch(l, p); e == nil {
				t.Fatal("unsupported guard authorized")
			}
		})
	}
	q, l, r, p := launchFixture(t)
	if _, e := q.RegisterLaunch(l, p); e != nil {
		t.Fatal(e)
	}
	r.GuardDigest = domain.Hash([]byte("different executed guard"))
	if _, e := q.RecordReceipt(l, r); e == nil {
		t.Fatal("receipt detached from approved guard")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n)
	if n != 0 {
		t.Fatal("mismatched guard persisted")
	}
}

func TestHistoricalGuardlessLaunchReadDoesNotAcquireNewExecutionAuthority(t *testing.T) {
	q, l, r, p := launchFixture(t)
	launch, e := q.RegisterLaunch(l, p)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := q.RecordReceipt(l, r)
	if e != nil {
		t.Fatal(e)
	}
	historical := launch.Document
	historical.Schema = "1.0"
	historical.GuardSet = ""
	historical.GuardProtocol = ""
	historical.Plan.Guard = ""
	historical.Plan.Architecture = ""
	b, e := json.Marshal(historical)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.S.DB.Exec("DROP TRIGGER scanner_launches_no_update"); e != nil {
		t.Fatal(e)
	}
	if _, e = q.S.DB.Exec("UPDATE scanner_launches SET document=?,digest=? WHERE job=? AND tool=?", string(b), domain.Hash(b), l.Job.ID, r.Tool); e != nil {
		t.Fatal(e)
	}
	rows, e := q.Launches(l.Job.Owner, l.Job.ID)
	if e != nil || len(rows) != 1 || rows[0].Document.Schema != "1.0" || rows[0].Document.GuardSet != "" {
		t.Fatal("historical launch reinterpreted", e)
	}
	if _, e = q.RegisterLaunch(l, p); !errors.Is(e, ErrConflict) {
		t.Fatal("old record acquired guard authority", e)
	}
	replay, e := q.RecordReceipt(l, r)
	if e != nil || replay.Digest != receipt.Digest {
		t.Fatal("committed evidence replay changed", e)
	}
}
