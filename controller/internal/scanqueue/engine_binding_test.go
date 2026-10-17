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

func TestOperatorEngineBindingIsImmutableAuditedAndSurvivesRestart(t *testing.T) {
	q, _, path := fixture(t)
	engine, registry := domain.Hash([]byte("engine")), domain.Hash([]byte("registry"))
	bound, e := q.BindEngine("owner-a", engine, registry)
	if e != nil || !bound.Valid("owner-a") {
		t.Fatal(bound, e)
	}
	again, e := q.BindEngine("owner-a", engine, registry)
	if e != nil || again != bound {
		t.Fatal(again, e)
	}
	for _, args := range [][3]string{{"owner-b", engine, registry}, {"owner-a", domain.Hash([]byte("other")), registry}, {"owner-a", engine, domain.Hash([]byte("other"))}, {"owner-a", "bad", registry}} {
		if _, e = q.BindEngine(args[0], args[1], args[2]); e == nil {
			t.Fatal("scope replaced")
		}
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE document LIKE '%scanner.engine_bind%'").Scan(&n)
	if n != 1 {
		t.Fatal(n)
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
	got, e := q.EngineBindingForWorker("trusted-worker", "owner-a")
	if e != nil || got != bound {
		t.Fatal(got, e)
	}
	if _, e = q.EngineBindingForWorker("trusted-worker", "owner-b"); e == nil {
		t.Fatal("cross-owner binding read")
	}
	q.S.DB.Exec("UPDATE scanner_workers SET state='revoked' WHERE id='trusted-worker'")
	if _, e = q.EngineBindingForWorker("trusted-worker", "owner-a"); !errors.Is(e, ErrLease) {
		t.Fatal("revoked read", e)
	}
}
func TestEngineBindingRequiresProvisionedIdleOwnerAndAuditCommit(t *testing.T) {
	for _, kind := range []string{"missing-owner", "missing-repo", "occupied", "audit-failure"} {
		t.Run(kind, func(t *testing.T) {
			q, in, _ := fixture(t)
			switch kind {
			case "missing-owner":
				q.S.DB.Exec("DELETE FROM settings WHERE key='repository_mount_owner'")
			case "missing-repo":
				if _, e := q.S.DB.Exec("UPDATE repositories SET owner='owner-b'"); e != nil {
					t.Fatal(e)
				}
			case "occupied":
				enqueueClaim(t, q, in)
			case "audit-failure":
				q.S.DB.Exec("CREATE TRIGGER block_binding_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END")
			}
			if _, e := q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry"))); e == nil {
				t.Fatal("unsafe provision accepted")
			}
			var count int
			q.S.DB.QueryRow("SELECT count(*) FROM settings WHERE key=?", engineBindingKey).Scan(&count)
			if count != 0 {
				t.Fatal("failed binding persisted")
			}
		})
	}
}
func TestConflictingConcurrentEngineProvisioningHasOneWinner(t *testing.T) {
	q, _, _ := fixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, engine := range []string{"one", "two"} {
		wg.Add(1)
		go func(engine string) {
			defer wg.Done()
			_, e := q.BindEngine("owner-a", domain.Hash([]byte(engine)), domain.Hash([]byte("registry")))
			results <- e
		}(engine)
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
func TestCorruptEngineBindingIsNotAnUnboundLegacyFallback(t *testing.T) {
	for _, kind := range []string{"malformed", "unknown", "duplicate", "hash", "owner", "future", "noncanonical"} {
		t.Run(kind, func(t *testing.T) {
			q, _, _ := fixture(t)
			r, e := q.BindEngine("owner-a", domain.Hash([]byte("engine")), domain.Hash([]byte("registry")))
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(r)
			switch kind {
			case "malformed":
				raw = []byte("{")
			case "unknown":
				raw = []byte(strings.Replace(string(raw), `{"binding_digest":`, `{"extra":true,"binding_digest":`, 1))
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `{"binding_digest":`, `{"binding_digest":"wrong","binding_digest":`, 1))
			case "hash":
				r.Digest = domain.Hash([]byte("wrong"))
				raw, _ = json.Marshal(r)
			case "owner":
				r.Document.Owner = "owner-b"
				r.Digest = domain.Digest(r.Document)
				raw, _ = json.Marshal(r)
			case "future":
				r.Document.Created = q.now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				r.Digest = domain.Digest(r.Document)
				raw, _ = json.Marshal(r)
			case "noncanonical":
				raw = append([]byte(" "), raw...)
			}
			q.S.DB.Exec("UPDATE settings SET value=? WHERE key=?", string(raw), engineBindingKey)
			if _, e = q.BindEngine("owner-a", r.Document.Engine, r.Document.Registry); e == nil {
				t.Fatal("corrupt binding replay")
			}
			if _, e = q.EngineBindingForWorker("trusted-worker", "owner-a"); e == nil || e == sql.ErrNoRows {
				t.Fatal("corrupt binding silently absent", e)
			}
		})
	}
}
func TestProvisionedEngineScopeConstrainsEveryLaunchBeforeRegistration(t *testing.T) {
	for _, kind := range []string{"match", "engine", "registry", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			q, in, _ := fixture(t)
			in.Tools = []string{"bandit"}
			q.Pins = map[string]Pin{"bandit": {"1.9.4", domain.Hash([]byte("fixture-image"))}}
			engine, registry := domain.Hash([]byte("engine")), domain.Hash([]byte("registry"))
			if _, e := q.BindEngine("owner-a", engine, registry); e != nil {
				t.Fatal(e)
			}
			l := enqueueClaim(t, q, in)
			m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
			for _, f := range m.Files {
				m.Bytes += f.Size
			}
			m.Digest = domain.Digest(m)
			p := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: engine, Registry: registry, Workspace: "run-" + strings.Repeat("a", 32), Snapshot: m.Digest, Guard: q.Guards.AMD64, Architecture: "amd64"}
			if kind == "engine" {
				p.Engine = domain.Hash([]byte("other"))
			}
			if kind == "registry" {
				p.Registry = domain.Hash([]byte("other"))
			}
			_, e := q.ReserveWorkspace(l, scanevidence.WorkspacePlan{Tool: p.Tool, Workspace: p.Workspace, Registry: p.Registry, Snapshot: p.Snapshot})
			if kind == "registry" {
				if !errors.Is(e, ErrConflict) {
					t.Fatal("wrong registry allocated", e)
				}
			} else if e != nil {
				t.Fatal(e)
			}
			if kind == "corrupt" {
				q.S.DB.Exec("UPDATE settings SET value='{}' WHERE key=?", engineBindingKey)
			}
			_, e = q.RegisterLaunch(l, p)
			var n int
			q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
			if kind == "match" {
				if e != nil || n != 1 {
					t.Fatal(e, n)
				}
			} else if !errors.Is(e, ErrConflict) || n != 0 {
				t.Fatal("unbound launch authorized", kind, e, n)
			}
			var state string
			q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
			if state != "active" {
				t.Fatal("binding check released admission", state)
			}
		})
	}
}
