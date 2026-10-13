// SPDX-License-Identifier: Apache-2.0
package store

import (
	"aegis.local/controller/internal/domain"
	"database/sql"
	"fmt"
)

const researchSchema = `
CREATE TABLE scope_grants(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),app TEXT NOT NULL,document TEXT NOT NULL,digest TEXT UNIQUE NOT NULL,state TEXT NOT NULL CHECK(state IN ('draft','active','revoked')),expires INTEGER NOT NULL,requests_used INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE research_jobs(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),app TEXT NOT NULL,kind TEXT NOT NULL,scope TEXT NOT NULL REFERENCES scope_grants(id),input_digest TEXT NOT NULL,request_digest TEXT NOT NULL,idempotency_key TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('queued','running','success','failed','cancelled','timeout')),payload TEXT NOT NULL,lease_token TEXT NOT NULL DEFAULT '',worker TEXT NOT NULL DEFAULT '',lease_until INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,cancel_requested INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,started INTEGER NOT NULL DEFAULT 0,finished_at TEXT NOT NULL DEFAULT '',error_code TEXT NOT NULL DEFAULT '',report_digest TEXT NOT NULL DEFAULT '',UNIQUE(owner,idempotency_key));
CREATE INDEX research_jobs_claim ON research_jobs(state,lease_until,created_at,id);
CREATE INDEX scope_grants_owner ON scope_grants(owner,created_at,id);
CREATE TABLE report_owners(digest TEXT NOT NULL REFERENCES reports(digest),owner TEXT NOT NULL REFERENCES owners(id),PRIMARY KEY(digest,owner));
INSERT INTO report_owners SELECT r.digest,o.id FROM reports r CROSS JOIN owners o WHERE (SELECT count(*) FROM owners)=1;
`

const repositorySchema = `
CREATE TABLE repositories(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),app TEXT NOT NULL,asset TEXT NOT NULL,map_digest TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(owner,app,asset));
CREATE TABLE application_maps(repository TEXT NOT NULL REFERENCES repositories(id),digest TEXT NOT NULL,document TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(repository,digest));
CREATE INDEX repositories_owner ON repositories(owner,created_at,id);
`

func migrate(db *sql.DB) error {
	versions := []string{schema, researchSchema, repositorySchema}
	var exists int
	if e := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='migrations'").Scan(&exists); e != nil {
		return e
	}
	applied := map[int]string{}
	if exists > 0 {
		rows, e := db.Query("SELECT version,checksum FROM migrations ORDER BY version")
		if e != nil {
			return e
		}
		for rows.Next() {
			var n int
			var hash string
			if e = rows.Scan(&n, &hash); e != nil {
				rows.Close()
				return e
			}
			applied[n] = hash
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	// Validate every existing version before any DDL touches the database.
	for n, hash := range applied {
		if n < 1 || n > len(versions) {
			return fmt.Errorf("database schema version unsupported")
		}
		if hash != domain.Hash([]byte(versions[n-1])) {
			return fmt.Errorf("migration checksum mismatch at version %d", n)
		}
		for prior := 1; prior < n; prior++ {
			if _, ok := applied[prior]; !ok {
				return fmt.Errorf("migration history has a gap")
			}
		}
	}
	for i, body := range versions {
		version := i + 1
		if _, ok := applied[version]; ok {
			continue
		}
		tx, e := db.Begin()
		if e != nil {
			return e
		}
		if _, e = tx.Exec(body); e == nil {
			_, e = tx.Exec("INSERT INTO migrations VALUES(?,?)", version, domain.Hash([]byte(body)))
		}
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
		if e != nil {
			return fmt.Errorf("migration %d failed: %w", version, e)
		}
	}
	return nil
}
