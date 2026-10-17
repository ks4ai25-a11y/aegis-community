// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestBrokerBindingSelectsOneWorkerBeforeClaimAndPersists(t *testing.T) {
	q, in, path := fixture(t)
	_, journal := provisionJournalFixture(t, q)
	bound, e := q.BindBroker("owner-a", "trusted-worker")
	if e != nil || bound.Document.Journal != journal.Digest {
		t.Fatal(bound, e)
	}
	again, e := q.BindBroker("owner-a", "trusted-worker")
	if e != nil || again != bound {
		t.Fatal(e)
	}
	if _, e = q.BindBroker("owner-a", "another-worker"); !errors.Is(e, ErrConflict) {
		t.Fatal("broker replaced", e)
	}
	if _, e = q.Enqueue("owner-a", "broker-job-key", in); e != nil {
		t.Fatal(e)
	}
	if _, e = q.Claim("another-worker", "owner-a"); !errors.Is(e, ErrLease) {
		t.Fatal("other worker claimed", e)
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 0 {
		t.Fatal("denied claim consumed admission")
	}
	q.S.DB.Close()
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	q.S = s
	got, e := q.BrokerBindingForWorker("trusted-worker", "owner-a")
	if e != nil || got != bound {
		t.Fatal(e)
	}
	if _, e = q.BrokerBindingForWorker("another-worker", "owner-a"); !errors.Is(e, ErrLease) {
		t.Fatal(e)
	}
	lease, e := q.Claim("trusted-worker", "owner-a")
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Fail(lease, "TOOL_UNAVAILABLE"); e != nil {
		t.Fatal(e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal(state)
	}
	if _, e = q.Claim("trusted-worker", "owner-a"); !errors.Is(e, ErrCleanup) {
		t.Fatal(e)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestBrokerBindingRefusesUnsafeProvisionAndRollsBack(t *testing.T) {
	for _, kind := range []string{"missing-journal", "wrong-owner", "unknown-worker", "revoked", "occupied", "audit-failure"} {
		t.Run(kind, func(t *testing.T) {
			q, in, _ := fixture(t)
			if kind != "missing-journal" {
				provisionJournalFixture(t, q)
			}
			owner, id := "owner-a", "trusted-worker"
			switch kind {
			case "wrong-owner":
				owner = "owner-b"
			case "unknown-worker":
				id = "unknown"
			case "revoked":
				q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id=?", id)
			case "occupied":
				enqueueClaim(t, q, in)
			case "audit-failure":
				q.S.DB.Exec("CREATE TRIGGER no_broker_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END")
			}
			if _, e := q.BindBroker(owner, id); e == nil {
				t.Fatal("unsafe broker provisioning")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM settings WHERE key=?", brokerBindingKey).Scan(&n)
			if n != 0 {
				t.Fatal("failed provision persisted")
			}
		})
	}
}
func TestCorruptBrokerBindingCannotFallBackToUnrestrictedWorker(t *testing.T) {
	for _, kind := range []string{"json", "hash", "owner", "journal", "future", "missing-parent", "noncanonical"} {
		t.Run(kind, func(t *testing.T) {
			q, in, _ := fixture(t)
			provisionJournalFixture(t, q)
			r, e := q.BindBroker("owner-a", "trusted-worker")
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "owner":
				r.Document.Owner = "owner-b"
			case "journal":
				r.Document.Journal = domain.Hash([]byte("other"))
			case "future":
				r.Document.Created = q.now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "missing-parent":
				q.S.DB.Exec("DELETE FROM settings WHERE key=?", journalBindingKey)
			}
			r.Digest = domain.Digest(r.Document)
			if kind == "hash" {
				r.Digest = domain.Hash([]byte("wrong"))
			}
			raw, _ := json.Marshal(r)
			if kind == "json" {
				raw = []byte("{")
			}
			if kind == "noncanonical" {
				raw = append([]byte(" "), raw...)
			}
			q.S.DB.Exec("UPDATE settings SET value=? WHERE key=?", string(raw), brokerBindingKey)
			if _, e = q.BindBroker("owner-a", "trusted-worker"); e == nil {
				t.Fatal("corrupt broker replaced")
			}
			q.Enqueue("owner-a", "corrupt-broker-job", in)
			if _, e = q.Claim("trusted-worker", "owner-a"); e == nil {
				t.Fatal("corrupt broker allowed claim")
			}
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
			if n != 0 {
				t.Fatal("corrupt claim consumed admission")
			}
		})
	}
}
func TestConflictingBrokerProvisionHasOneWinner(t *testing.T) {
	q, _, _ := fixture(t)
	provisionJournalFixture(t, q)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"trusted-worker", "another-worker"} {
		wg.Add(1)
		go func(id string) { defer wg.Done(); _, e := q.BindBroker("owner-a", id); results <- e }(id)
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
}
