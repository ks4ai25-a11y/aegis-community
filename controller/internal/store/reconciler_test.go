// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"aegis.local/controller/internal/domain"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestReconcilerMigrationPreservesVersionSixteenHoldsAndPendingMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version16.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	previous := migrationBodies()[:16]
	for n, body := range previous {
		if _, err = db.Exec(body); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec("INSERT INTO migrations VALUES(?,?)", n+1, domain.Hash([]byte(body))); err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{
		"INSERT INTO owners VALUES('owner','fixture','2026-10-17T00:00:00Z')",
		"INSERT INTO repositories VALUES('repo','owner','app_demo','fixture','map','2026-10-17T00:00:00Z')",
		"INSERT INTO application_maps VALUES('repo','map','{}','2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_workers VALUES('worker','owner','worker-hash','active',2147483647,'2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_verifiers VALUES('observer','owner','observer-hash','active','engine','registry',2147483647,'2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_authorizers VALUES('authorizer','owner','authorizer-hash','active','engine','registry','policy',2147483647,'2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('job','owner','repo','app_demo','map','lock','request','key','{}','running','2026-10-17T00:00:00Z',2147483647)",
		"INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state) VALUES(1,'job','worker','original-lease',0,2147483647,'cleanup_required')",
		"INSERT INTO scanner_mutation_bindings VALUES('binding','owner','authorizer','engine','registry','policy','namespace','broker','2026-10-17T00:00:00Z','active')",
		"INSERT INTO scanner_allocation_generations(job,id,owner,worker,binding_digest,lease_hash,deadline,guard_digest,created_at,state) VALUES('job','generation','owner','worker','binding','original-lease',2147483647,'guard','2026-10-17T00:00:00Z','closed')",
		"INSERT INTO scanner_mutation_intents(id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,created_at,state) VALUES('intent','generation','job','bandit','create','launch','workspace','container','descriptor','','2026-10-17T00:00:00Z','pending')",
	} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	for n, body := range previous {
		var checksum string
		if err = s.DB.QueryRow("SELECT checksum FROM migrations WHERE version=?", n+1).Scan(&checksum); err != nil || checksum != domain.Hash([]byte(body)) {
			t.Fatal("prior migration changed", err)
		}
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM scanner_reconcilers").Scan(&count); err != nil || count != 0 {
		t.Fatal("upgrade created independent confirmation authority", err)
	}
	var state, descriptor, response string
	if err = s.DB.QueryRow("SELECT state,descriptor_digest,response_digest FROM scanner_mutation_intents WHERE id='intent'").Scan(&state, &descriptor, &response); err != nil || state != "pending" || descriptor != "descriptor" || response != "" {
		t.Fatal("upgrade settled pending mutation", err)
	}
	if err = s.DB.QueryRow("SELECT state FROM scanner_allocation_generations WHERE job='job'").Scan(&state); err != nil || state != "closed" {
		t.Fatal("upgrade changed generation", err)
	}
	if err = s.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job='job'").Scan(&state); err != nil || state != "cleanup_required" {
		t.Fatal("upgrade released hold", err)
	}
	if err = s.DB.QueryRow("SELECT state FROM scanner_verifiers WHERE id='observer'").Scan(&state); err != nil || state != "active" {
		t.Fatal("existing observer enrollment changed", err)
	}
}
