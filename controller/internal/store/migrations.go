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

// New version only: previously deployed migration bodies remain immutable.
const scannerSchema = `
CREATE TABLE scanner_jobs(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),repository TEXT NOT NULL REFERENCES repositories(id),app TEXT NOT NULL,map_digest TEXT NOT NULL,lock_digest TEXT NOT NULL,request_digest TEXT NOT NULL,idempotency_key TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('queued','running','completed','completed_partial','completed_stale_db','tool_error','cancelled','timeout')),cancel_requested INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,expires INTEGER NOT NULL,finished_at TEXT NOT NULL DEFAULT '',error_code TEXT NOT NULL DEFAULT '',UNIQUE(owner,idempotency_key),FOREIGN KEY(repository,map_digest) REFERENCES application_maps(repository,digest));
CREATE INDEX scanner_jobs_claim ON scanner_jobs(state,expires,created_at,id);
CREATE INDEX scanner_jobs_owner ON scanner_jobs(owner,created_at,id);
`

const scannerLeaseSchema = `
CREATE TABLE scanner_dispatch(slot INTEGER PRIMARY KEY CHECK(slot=1),job TEXT UNIQUE NOT NULL REFERENCES scanner_jobs(id),worker TEXT NOT NULL,token_hash TEXT NOT NULL,lease_until INTEGER NOT NULL,deadline INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','cleanup_required')));
`

const scannerWorkerSchema = `
CREATE TABLE scanner_workers(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),token_hash TEXT UNIQUE NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoked')),expires INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX scanner_workers_owner ON scanner_workers(owner,state,expires);
`

// Receipts are append-only under the controller/local-host trust boundary.
const scannerReceiptSchema = `
CREATE TABLE scanner_receipts(job TEXT NOT NULL REFERENCES scanner_jobs(id),tool TEXT NOT NULL,owner TEXT NOT NULL REFERENCES owners(id),request_digest TEXT NOT NULL,digest TEXT UNIQUE NOT NULL,document TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(job,tool));
CREATE INDEX scanner_receipts_owner ON scanner_receipts(owner,job,tool);
CREATE TRIGGER scanner_receipts_no_update BEFORE UPDATE ON scanner_receipts BEGIN SELECT RAISE(ABORT,'scanner receipt is immutable'); END;
CREATE TRIGGER scanner_receipts_no_delete BEFORE DELETE ON scanner_receipts BEGIN SELECT RAISE(ABORT,'scanner receipt is immutable'); END;
`

const scannerResultSchema = `
CREATE TABLE scanner_results(job TEXT PRIMARY KEY REFERENCES scanner_jobs(id),owner TEXT NOT NULL REFERENCES owners(id),request_digest TEXT NOT NULL,digest TEXT UNIQUE NOT NULL,document TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX scanner_results_owner ON scanner_results(owner,job);
CREATE TRIGGER scanner_results_no_update BEFORE UPDATE ON scanner_results BEGIN SELECT RAISE(ABORT,'scanner result is immutable'); END;
CREATE TRIGGER scanner_results_no_delete BEFORE DELETE ON scanner_results BEGIN SELECT RAISE(ABORT,'scanner result is immutable'); END;
`

const scannerLaunchSchema = `
ALTER TABLE scanner_dispatch ADD COLUMN launch_protocol INTEGER NOT NULL DEFAULT 0 CHECK(launch_protocol IN (0,1));
CREATE TABLE scanner_launches(job TEXT NOT NULL REFERENCES scanner_jobs(id),tool TEXT NOT NULL,owner TEXT NOT NULL REFERENCES owners(id),request_digest TEXT NOT NULL,container TEXT UNIQUE NOT NULL,workspace TEXT UNIQUE NOT NULL,digest TEXT UNIQUE NOT NULL,document TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(job,tool));
CREATE INDEX scanner_launches_owner ON scanner_launches(owner,job,tool);
CREATE TRIGGER scanner_launches_no_update BEFORE UPDATE ON scanner_launches BEGIN SELECT RAISE(ABORT,'scanner launch is immutable'); END;
CREATE TRIGGER scanner_launches_no_delete BEFORE DELETE ON scanner_launches BEGIN SELECT RAISE(ABORT,'scanner launch is immutable'); END;
`

const scannerWorkspaceSchema = `
ALTER TABLE scanner_dispatch ADD COLUMN workspace_protocol INTEGER NOT NULL DEFAULT 0 CHECK(workspace_protocol IN (0,1));
CREATE TABLE scanner_workspaces(job TEXT NOT NULL REFERENCES scanner_jobs(id),tool TEXT NOT NULL,owner TEXT NOT NULL REFERENCES owners(id),request_digest TEXT NOT NULL,workspace TEXT UNIQUE NOT NULL,digest TEXT UNIQUE NOT NULL,document TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(job,tool));
CREATE INDEX scanner_workspaces_owner ON scanner_workspaces(owner,job,tool);
CREATE TRIGGER scanner_workspaces_no_update BEFORE UPDATE ON scanner_workspaces BEGIN SELECT RAISE(ABORT,'scanner workspace is immutable'); END;
CREATE TRIGGER scanner_workspaces_no_delete BEFORE DELETE ON scanner_workspaces BEGIN SELECT RAISE(ABORT,'scanner workspace is immutable'); END;
`

const scannerGuardSchema = `
ALTER TABLE scanner_dispatch ADD COLUMN guard_set_digest TEXT NOT NULL DEFAULT '';
`

const findingTriageSchema = `
CREATE TABLE finding_triage(job TEXT NOT NULL REFERENCES scanner_jobs(id),record TEXT NOT NULL,owner TEXT NOT NULL REFERENCES owners(id),result_digest TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 50),idempotency_key TEXT NOT NULL,request_digest TEXT NOT NULL,digest TEXT UNIQUE NOT NULL,document TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(job,record,revision),UNIQUE(owner,idempotency_key));
CREATE INDEX finding_triage_owner ON finding_triage(owner,job,record,revision DESC);
CREATE TRIGGER finding_triage_no_update BEFORE UPDATE ON finding_triage BEGIN SELECT RAISE(ABORT,'finding triage is immutable'); END;
CREATE TRIGGER finding_triage_no_delete BEFORE DELETE ON finding_triage BEGIN SELECT RAISE(ABORT,'finding triage is immutable'); END;
`

const scannerVerifierSchema = `
CREATE TABLE scanner_verifiers(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),token_hash TEXT UNIQUE NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoked')),engine_digest TEXT NOT NULL,registry_digest TEXT NOT NULL,expires INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX scanner_verifiers_owner ON scanner_verifiers(owner,state,expires);
CREATE TRIGGER scanner_verifiers_scope_immutable BEFORE UPDATE OF id,owner,token_hash,engine_digest,registry_digest,expires,created_at ON scanner_verifiers BEGIN SELECT RAISE(ABORT,'scanner verifier scope is immutable'); END;
CREATE TRIGGER scanner_verifiers_state_monotonic BEFORE UPDATE OF state ON scanner_verifiers WHEN OLD.state!='active' OR NEW.state!='revoked' BEGIN SELECT RAISE(ABORT,'scanner verifier cannot be reactivated'); END;
CREATE TRIGGER scanner_verifiers_no_delete BEFORE DELETE ON scanner_verifiers BEGIN SELECT RAISE(ABORT,'scanner verifier enrollment is retained'); END;
`

func migrationBodies() []string {
	return []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema, scannerReceiptSchema, scannerResultSchema, scannerLaunchSchema, scannerWorkspaceSchema, scannerGuardSchema, findingTriageSchema, scannerVerifierSchema}
}
func migrate(db *sql.DB) error {
	versions := migrationBodies()
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
