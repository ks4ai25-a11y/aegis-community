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

// Distinct from read-only verifier enrollment. Admission operations are added
// separately; an enrolled identity alone never settles or releases a job.
const scannerAuthorizerSchema = `
CREATE TABLE scanner_authorizers(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),token_hash TEXT UNIQUE NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoked')),engine_digest TEXT NOT NULL,registry_digest TEXT NOT NULL,policy_digest TEXT NOT NULL,expires INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX scanner_authorizers_owner ON scanner_authorizers(owner,state,expires);
CREATE TRIGGER scanner_authorizers_scope_immutable BEFORE UPDATE OF id,owner,token_hash,engine_digest,registry_digest,policy_digest,expires,created_at ON scanner_authorizers BEGIN SELECT RAISE(ABORT,'scanner authorizer scope is immutable'); END;
CREATE TRIGGER scanner_authorizers_state_monotonic BEFORE UPDATE OF state ON scanner_authorizers WHEN OLD.state!='active' OR NEW.state!='revoked' BEGIN SELECT RAISE(ABORT,'scanner authorizer cannot be reactivated'); END;
CREATE TRIGGER scanner_authorizers_no_delete BEFORE DELETE ON scanner_authorizers BEGIN SELECT RAISE(ABORT,'scanner authorizer enrollment is retained'); END;
`

// Migration 015: owner-issued, read-only connector credentials for local MCP
// bridges and other assistants. Only a hash of the token is stored; scope is
// immutable and revocation is one-way.
const connectorCredentialSchema = `
CREATE TABLE connector_credentials(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),token_hash TEXT UNIQUE NOT NULL,scope TEXT NOT NULL CHECK(scope='read_defence_v1'),state TEXT NOT NULL CHECK(state IN ('active','revoked')),created_at TEXT NOT NULL,expires INTEGER NOT NULL,last_used INTEGER NOT NULL DEFAULT 0);
CREATE INDEX connector_credentials_owner ON connector_credentials(owner,state,expires);
CREATE TRIGGER connector_credentials_scope_immutable BEFORE UPDATE OF id,owner,name,token_hash,scope,created_at,expires ON connector_credentials BEGIN SELECT RAISE(ABORT,'connector credential scope is immutable'); END;
CREATE TRIGGER connector_credentials_state_monotonic BEFORE UPDATE OF state ON connector_credentials WHEN OLD.state!='active' OR NEW.state!='revoked' BEGIN SELECT RAISE(ABORT,'connector credential cannot be reactivated'); END;
`

// scannerAllocationSchema is migration 016. Intents are retained obligations,
// not evidence of execution or absence. Closure never settles an intent.
const scannerAllocationSchema = `
CREATE TABLE scanner_mutation_bindings(digest TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES owners(id),authorizer TEXT NOT NULL REFERENCES scanner_authorizers(id),engine_digest TEXT NOT NULL,registry_digest TEXT NOT NULL,policy_digest TEXT NOT NULL,namespace_digest TEXT NOT NULL,broker_binding_digest TEXT NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','revoked')));
CREATE UNIQUE INDEX scanner_mutation_binding_active ON scanner_mutation_bindings(owner) WHERE state='active';
CREATE TRIGGER scanner_mutation_binding_immutable BEFORE UPDATE OF digest,owner,authorizer,engine_digest,registry_digest,policy_digest,namespace_digest,broker_binding_digest,created_at ON scanner_mutation_bindings BEGIN SELECT RAISE(ABORT,'mutation binding is immutable'); END;
CREATE TRIGGER scanner_mutation_binding_monotonic BEFORE UPDATE OF state ON scanner_mutation_bindings WHEN OLD.state!='active' OR NEW.state!='revoked' BEGIN SELECT RAISE(ABORT,'mutation binding cannot reactivate'); END;
CREATE TRIGGER scanner_mutation_binding_retained BEFORE DELETE ON scanner_mutation_bindings BEGIN SELECT RAISE(ABORT,'mutation binding history is retained'); END;
CREATE TABLE scanner_allocation_generations(job TEXT PRIMARY KEY REFERENCES scanner_jobs(id),id TEXT UNIQUE NOT NULL,owner TEXT NOT NULL REFERENCES owners(id),worker TEXT NOT NULL REFERENCES scanner_workers(id),binding_digest TEXT NOT NULL REFERENCES scanner_mutation_bindings(digest),lease_hash TEXT NOT NULL,deadline INTEGER NOT NULL,guard_digest TEXT NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('open','closed','released')),closed_at TEXT NOT NULL DEFAULT '');
CREATE TRIGGER scanner_generation_immutable BEFORE UPDATE OF job,id,owner,worker,binding_digest,lease_hash,deadline,guard_digest,created_at ON scanner_allocation_generations BEGIN SELECT RAISE(ABORT,'generation identity is immutable'); END;
CREATE TRIGGER scanner_generation_monotonic BEFORE UPDATE OF state ON scanner_allocation_generations WHEN NOT ((OLD.state='open' AND NEW.state='closed') OR (OLD.state='closed' AND NEW.state='released')) BEGIN SELECT RAISE(ABORT,'generation cannot reopen'); END;
CREATE TRIGGER scanner_generation_retained BEFORE DELETE ON scanner_allocation_generations BEGIN SELECT RAISE(ABORT,'generation history is retained'); END;
CREATE TABLE scanner_mutation_intents(id TEXT PRIMARY KEY,generation TEXT NOT NULL REFERENCES scanner_allocation_generations(id),job TEXT NOT NULL REFERENCES scanner_jobs(id),tool TEXT NOT NULL,operation TEXT NOT NULL CHECK(operation IN ('create','start','remove')),launch_digest TEXT NOT NULL,workspace_digest TEXT NOT NULL,container TEXT NOT NULL,descriptor_digest TEXT NOT NULL,target_engine_id TEXT NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','completed')),response_digest TEXT NOT NULL DEFAULT '',response_status INTEGER NOT NULL DEFAULT 0,result_engine_id TEXT NOT NULL DEFAULT '',completed_at TEXT NOT NULL DEFAULT '',UNIQUE(generation,tool,operation));
CREATE TRIGGER scanner_mutation_intent_immutable BEFORE UPDATE OF id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,created_at ON scanner_mutation_intents BEGIN SELECT RAISE(ABORT,'mutation intent is immutable'); END;
CREATE TRIGGER scanner_mutation_completion_once BEFORE UPDATE OF state,response_digest,response_status,result_engine_id,completed_at ON scanner_mutation_intents WHEN OLD.state!='pending' OR NEW.state!='completed' OR NEW.response_digest='' OR NEW.completed_at='' OR NOT ((NEW.operation='create' AND NEW.response_status=201 AND length(NEW.result_engine_id)=64) OR (NEW.operation IN ('start','remove') AND NEW.response_status=204 AND NEW.result_engine_id=NEW.target_engine_id)) BEGIN SELECT RAISE(ABORT,'mutation completion is immutable'); END;
CREATE TRIGGER scanner_mutation_intent_retained BEFORE DELETE ON scanner_mutation_intents BEGIN SELECT RAISE(ABORT,'mutation obligations are retained'); END;
CREATE TRIGGER scanner_generation_job_closed AFTER UPDATE OF state,cancel_requested ON scanner_jobs WHEN NEW.state!='running' OR NEW.cancel_requested!=0 BEGIN UPDATE scanner_allocation_generations SET state='closed',closed_at=CASE WHEN NEW.finished_at!='' THEN NEW.finished_at ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END WHERE job=NEW.id AND state='open'; END;
CREATE TRIGGER scanner_generation_dispatch_closed AFTER UPDATE OF state ON scanner_dispatch WHEN NEW.state!='active' BEGIN UPDATE scanner_allocation_generations SET state='closed',closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE job=NEW.job AND state='open'; END;
CREATE TRIGGER scanner_generation_authorizer_revoked AFTER UPDATE OF state ON scanner_authorizers WHEN NEW.state='revoked' BEGIN UPDATE scanner_allocation_generations SET state='closed',closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state='open' AND binding_digest IN (SELECT digest FROM scanner_mutation_bindings WHERE authorizer=NEW.id); END;
CREATE TRIGGER scanner_generation_worker_revoked AFTER UPDATE OF state ON scanner_workers WHEN NEW.state='revoked' BEGIN UPDATE scanner_allocation_generations SET state='closed',closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state='open' AND worker=NEW.id; END;
CREATE TRIGGER scanner_generation_binding_revoked AFTER UPDATE OF state ON scanner_mutation_bindings WHEN NEW.state='revoked' BEGIN UPDATE scanner_allocation_generations SET state='closed',closed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state='open' AND binding_digest=NEW.digest; END;
CREATE TRIGGER scanner_generation_dispatch_held BEFORE DELETE ON scanner_dispatch WHEN EXISTS (SELECT 1 FROM scanner_allocation_generations WHERE job=OLD.job AND state!='released') BEGIN SELECT RAISE(ABORT,'generation awaits independent cleanup confirmation'); END;
`

func migrationBodies() []string {
	return []string{schema, researchSchema, repositorySchema, scannerSchema, scannerLeaseSchema, scannerWorkerSchema, scannerReceiptSchema, scannerResultSchema, scannerLaunchSchema, scannerWorkspaceSchema, scannerGuardSchema, findingTriageSchema, scannerVerifierSchema, scannerAuthorizerSchema, connectorCredentialSchema, scannerAllocationSchema}
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
