// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func provisionJournalFixture(t *testing.T, q *Queue) (scanevidence.EngineBindingRecord, scanevidence.JournalBindingRecord) {
	t.Helper()
	base, e := q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry")))
	if e != nil {
		t.Fatal(e)
	}
	bound, e := q.BindJournal("owner-a", domain.Hash([]byte("root")), domain.Hash([]byte("namespace")))
	if e != nil {
		t.Fatal(e)
	}
	return base, bound
}
func TestJournalBindingIsImmutableAuditedAndRestarted(t *testing.T) {
	q, _, path := fixture(t)
	base, bound := provisionJournalFixture(t, q)
	if !bound.Valid("owner-a", base) {
		t.Fatal(bound)
	}
	again, e := q.BindJournal("owner-a", bound.Document.Root, bound.Document.Namespace)
	if e != nil || again != bound {
		t.Fatal(e)
	}
	for _, args := range [][3]string{{"owner-b", bound.Document.Root, bound.Document.Namespace}, {"owner-a", domain.Hash([]byte("different")), bound.Document.Namespace}, {"owner-a", bound.Document.Root, domain.Hash([]byte("different"))}} {
		if _, e = q.BindJournal(args[0], args[1], args[2]); e == nil {
			t.Fatal("journal scope replaced")
		}
	}
	var count int
	q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE document LIKE '%scanner.journal_bind%'").Scan(&count)
	if count != 1 {
		t.Fatal(count)
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
	q.S = s
	got, e := q.JournalBindingForWorker("trusted-worker", "owner-a")
	if e != nil || got != bound {
		t.Fatal(got, e)
	}
	q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id='trusted-worker'")
	if _, e = q.JournalBindingForWorker("trusted-worker", "owner-a"); !errors.Is(e, ErrLease) {
		t.Fatal(e)
	}
}
func TestJournalProvisioningRequiresIdleEngineScopeAndAtomicAudit(t *testing.T) {
	for _, kind := range []string{"missing-base", "occupied", "audit-failure"} {
		t.Run(kind, func(t *testing.T) {
			q, in, _ := fixture(t)
			if kind != "missing-base" {
				if _, e := q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry"))); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "occupied" {
				enqueueClaim(t, q, in)
			}
			if kind == "audit-failure" {
				q.S.DB.Exec("CREATE TRIGGER block_journal_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END")
			}
			if _, e := q.BindJournal("owner-a", domain.Hash([]byte("root")), domain.Hash([]byte("namespace"))); e == nil {
				t.Fatal("unsafe provision")
			}
			var count int
			q.S.DB.QueryRow("SELECT count(*) FROM settings WHERE key=?", journalBindingKey).Scan(&count)
			if count != 0 {
				t.Fatal("partial journal authority")
			}
		})
	}
}
func TestConcurrentJournalProvisioningHasOneWinner(t *testing.T) {
	q, _, _ := fixture(t)
	q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry")))
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, n := range []string{"one", "two"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			_, e := q.BindJournal("owner-a", domain.Hash([]byte("root")), domain.Hash([]byte(n)))
			results <- e
		}(n)
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
func TestCorruptJournalProvisioningNeverFallsBackToLegacy(t *testing.T) {
	for _, kind := range []string{"malformed", "unknown", "duplicate", "digest", "owner", "base", "missing-base", "future", "before-base"} {
		t.Run(kind, func(t *testing.T) {
			q, _, _ := fixture(t)
			_, r := provisionJournalFixture(t, q)
			d := r.Document
			switch kind {
			case "owner":
				d.Owner = "owner-b"
			case "base":
				d.EngineBinding = domain.Hash([]byte("other"))
			case "future":
				d.Created = q.now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "before-base":
				d.Created = q.now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			}
			r.Document = d
			r.Digest = domain.Digest(d)
			if kind == "digest" {
				r.Digest = domain.Hash([]byte("wrong"))
			}
			raw, _ := json.Marshal(r)
			switch kind {
			case "malformed":
				raw = []byte("{")
			case "unknown":
				raw = []byte(strings.Replace(string(raw), `{"journal_binding_digest":`, `{"extra":true,"journal_binding_digest":`, 1))
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `{"journal_binding_digest":`, `{"journal_binding_digest":"wrong","journal_binding_digest":`, 1))
			case "missing-base":
				q.S.DB.Exec("DELETE FROM settings WHERE key=?", engineBindingKey)
			}
			q.S.DB.Exec("UPDATE settings SET value=? WHERE key=?", string(raw), journalBindingKey)
			if _, e := q.JournalBindingForWorker("trusted-worker", "owner-a"); e == nil {
				t.Fatal("corrupt journal read")
			}
			if _, e := q.BindJournal("owner-a", d.Root, d.Namespace); e == nil {
				t.Fatal("corrupt scope replaced")
			}
		})
	}
}
func TestJournalBoundLaunchRejectsDowngradeAndChangedNamespace(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "namespace", "binding", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			q, in, _ := fixture(t)
			_, bound := provisionJournalFixture(t, q)
			in.Tools = []string{"bandit"}
			q.Pins = map[string]Pin{"bandit": {"1.9.4", domain.Hash([]byte("image"))}}
			l := enqueueClaim(t, q, in)
			m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
			for _, f := range m.Files {
				m.Bytes += f.Size
			}
			m.Digest = domain.Digest(m)
			p := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: domain.Hash([]byte("engine")), Registry: domain.Hash([]byte("registry")), Workspace: "run-" + strings.Repeat("a", 32), Snapshot: m.Digest, Guard: q.Guards.AMD64, Architecture: "amd64", JournalBinding: bound.Digest, JournalNamespace: bound.Document.Namespace}
			reserveLaunchWorkspace(t, q, l, p)
			switch kind {
			case "missing":
				p.JournalBinding = ""
				p.JournalNamespace = ""
			case "namespace":
				p.JournalNamespace = domain.Hash([]byte("new"))
			case "binding":
				p.JournalBinding = domain.Hash([]byte("new"))
			case "corrupt":
				q.S.DB.Exec("UPDATE settings SET value='{}' WHERE key=?", journalBindingKey)
			}
			r, e := q.RegisterLaunch(l, p)
			if kind == "valid" {
				if e != nil || r.Document.Schema != "1.2" || !scanevidence.GuardedLaunchRevision(r.Document) {
					t.Fatal(r, e)
				}
				again, e := q.RegisterLaunch(l, p)
				if e != nil || again != r {
					t.Fatal(e)
				}
				if _, e = q.Launches("owner-a", l.Job.ID); e != nil {
					t.Fatal(e)
				}
			} else if !errors.Is(e, ErrConflict) {
				t.Fatal("journal downgrade allowed", kind, e)
			}
			var count int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&count)
			expected := 0
			if kind == "valid" {
				expected = 1
			}
			if count != expected {
				t.Fatal(count)
			}
		})
	}
}
func TestJournalBindingInitialProvisioningRefusesHeldSlotButExactReplayIsMetadataOnly(t *testing.T) {
	q, in, _ := fixture(t)
	_, bound := provisionJournalFixture(t, q)
	l := enqueueClaim(t, q, in)
	if e := q.Fail(l, "TOOL_UNAVAILABLE"); e != nil {
		t.Fatal(e)
	}
	again, e := q.BindJournal("owner-a", bound.Document.Root, bound.Document.Namespace)
	if e != nil || again != bound {
		t.Fatal(e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "cleanup_required" {
		t.Fatal(state)
	}
	q.S.DB.Exec("DELETE FROM settings WHERE key=?", journalBindingKey)
	if _, e = q.BindJournal("owner-a", bound.Document.Root, bound.Document.Namespace); !errors.Is(e, ErrCleanup) {
		t.Fatal("provisioning cleared hold", e)
	}
	if _, e = q.JournalBindingForWorker("trusted-worker", "owner-b"); e == nil || e == sql.ErrNoRows {
		t.Fatal("owner override", e)
	}
}
