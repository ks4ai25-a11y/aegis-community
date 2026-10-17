// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"aegis.local/controller/internal/domain"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// Migration 020 rebuilds the intent table. Every retained row, the earlier
// checksums and the obligation triggers must survive the rebuild unchanged.
func TestRepairMigrationRebuildsIntentsPreservingRowsAndTriggers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version19.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	previous := migrationBodies()[:19]
	for n, body := range previous {
		if _, err = db.Exec(body); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec("INSERT INTO migrations VALUES(?,?)", n+1, domain.Hash([]byte(body))); err != nil {
			t.Fatal(err)
		}
	}
	engine := strings.Repeat("c", 64)
	for _, statement := range []string{
		"INSERT INTO owners VALUES('owner','fixture','2026-10-17T00:00:00Z')",
		"INSERT INTO repositories VALUES('repo','owner','app_demo','fixture','map','2026-10-17T00:00:00Z')",
		"INSERT INTO application_maps VALUES('repo','map','{}','2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_workers VALUES('worker','owner','worker-hash','active',2147483647,'2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_authorizers VALUES('authorizer','owner','authorizer-hash','active','engine','registry','policy',2147483647,'2026-10-17T00:00:00Z')",
		"INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES('job','owner','repo','app_demo','map','lock','request','key','{}','running','2026-10-17T00:00:00Z',2147483647)",
		"INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state) VALUES(1,'job','worker','original-lease',0,2147483647,'cleanup_required')",
		"INSERT INTO scanner_mutation_bindings VALUES('binding','owner','authorizer','engine','registry','policy','namespace','broker','2026-10-17T00:00:00Z','active')",
		"INSERT INTO scanner_allocation_generations(job,id,owner,worker,binding_digest,lease_hash,deadline,guard_digest,created_at,state) VALUES('job','generation','owner','worker','binding','original-lease',2147483647,'guard','2026-10-17T00:00:00Z','closed')",
		"INSERT INTO scanner_mutation_intents(id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,created_at,state,response_digest,response_status,result_engine_id,completed_at) VALUES('created','generation','job','bandit','create','launch','workspace','container','descriptor','','2026-10-17T00:00:00Z','completed','response',201,'" + engine + "','2026-10-17T00:00:01Z')",
		"INSERT INTO scanner_mutation_intents(id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,created_at,state) VALUES('start','generation','job','bandit','start','launch','workspace','container','descriptor','" + engine + "','2026-10-17T00:00:02Z','pending')",
	} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	type row struct{ id, state, response, engine, completed string }
	read := func(q *sql.DB) []row {
		rows, err := q.Query("SELECT id,state,response_digest,result_engine_id,completed_at FROM scanner_mutation_intents ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err = rows.Scan(&r.id, &r.state, &r.response, &r.engine, &r.completed); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	before := read(db)
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
	after := read(s.DB)
	if len(after) != len(before) || len(after) != 2 {
		t.Fatal("rebuild lost intents", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("rebuild changed an intent", before[i], after[i])
		}
	}
	var integrity string
	if err = s.DB.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("rebuilt database inconsistent", integrity, err)
	}
	if rows, err := s.DB.Query("PRAGMA foreign_key_check"); err != nil || rows.Next() {
		t.Fatal("rebuilt intents broke a foreign key", err)
	} else {
		rows.Close()
	}
	for _, statement := range []string{
		"UPDATE scanner_mutation_intents SET container='other' WHERE id='start'",
		"DELETE FROM scanner_mutation_intents WHERE id='start'",
		"UPDATE scanner_mutation_intents SET state='repaired',response_digest='forged',completed_at='x' WHERE id='start'",
		"UPDATE scanner_mutation_intents SET state='completed',response_digest='r',response_status=200,result_engine_id='" + engine + "',completed_at='x' WHERE id='start'",
		"UPDATE scanner_mutation_intents SET state='pending',response_digest='',response_status=0,result_engine_id='',completed_at='' WHERE id='created'",
		"INSERT INTO scanner_mutation_repairs(intent,generation,job,reconciler,outcome,engine_id,digest,document,created_at) VALUES('created','generation','job','reconciler','created','" + engine + "','sha256:" + strings.Repeat("0", 64) + "','{}','x')",
	} {
		if _, err = s.DB.Exec(statement); err == nil {
			t.Fatal("rebuilt intent table accepted:", statement)
		}
	}
	// The native completion path is unchanged.
	if _, err = s.DB.Exec("UPDATE scanner_mutation_intents SET state='completed',response_digest='r',response_status=204,result_engine_id=?,completed_at='x' WHERE id='start'", engine); err != nil {
		t.Fatal("native completion refused after rebuild", err)
	}
}
