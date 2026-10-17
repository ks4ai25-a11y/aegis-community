// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"encoding/json"
)

// RepairMutations resolves every pending intent of one closed generation from
// a reconciler's evidence (ADR 057 sealed crash repair). The reconciler must
// already have verified the alpha-side fence: the plugin journal sealed in
// quarantine, and a daemon activated after that seal. The controller cannot
// observe the engine; it rechecks scope, closure and complete membership in
// this transaction, binds the fence to the generation's own journal seal, and
// records one retained repair per intent. Any mismatch refuses everything.
func (q *Queue) RepairMutations(ctx context.Context, v scanevidence.ReconcilerIdentity, r scanevidence.MutationRepairRequest) (scanevidence.MutationRepairResult, error) {
	if !r.Valid() {
		return scanevidence.MutationRepairResult{}, ErrInput
	}
	tx, err := q.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	defer tx.Rollback()
	if err = scannerauth.AuthorizeReconcilerTx(tx, v, q.now().Unix()); err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	m, err := membershipTx(ctx, tx, v, r.Job, r.Generation)
	if err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	// Admission is closed (membershipTx requires a closed generation), the job
	// is terminal and its slot is held: no new create or start can be admitted.
	if m.JobState == "queued" || m.JobState == "running" || m.Dispatch != "cleanup_required" || !m.Valid() {
		return scanevidence.MutationRepairResult{}, ErrContextUnbound
	}
	// A restored or revoked binding stays held, exactly as for release.
	var live int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM scanner_mutation_bindings b JOIN scanner_authorizers a ON a.id=b.authorizer AND a.owner=b.owner WHERE b.digest=? AND b.owner=? AND b.state='active' AND a.state='active'", v.Binding, v.Owner).Scan(&live); err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	if live != 1 {
		return scanevidence.MutationRepairResult{}, ErrContextUnbound
	}
	b := m.Binding.Document
	if scanevidence.ReconciliationMembershipDigest(m) != r.Membership || b.Engine != r.Engine || b.Namespace != r.Namespace || r.Fence.Policy != scanevidence.AdmittedJournalSeal(b.Policy, m.Binding.Digest) {
		return scanevidence.MutationRepairResult{}, ErrConflict
	}
	pending := scanevidence.PendingIntents(m)
	if len(pending) != len(r.Resolutions) {
		return scanevidence.MutationRepairResult{}, ErrConflict
	}
	settled := map[string]scanevidence.MutationIntent{}
	for _, x := range m.Mutations {
		if x.Settled() {
			settled[x.Request.Tool+"/"+x.Request.Operation] = x
		}
	}
	for i, x := range r.Resolutions {
		p := pending[i]
		if !x.ValidFor(p) {
			return scanevidence.MutationRepairResult{}, ErrConflict
		}
		// A start or remove only exists after a create settled with this exact
		// engine ID; re-derive it rather than trusting the resolution.
		if p.Request.Operation != "create" {
			created := settled[p.Request.Tool+"/create"]
			if created.EngineID == "" || created.EngineID != p.Request.EngineID {
				return scanevidence.MutationRepairResult{}, ErrConflict
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	if err = scannerauth.AuthorizeReconcilerTx(tx, v, q.now().Unix()); err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	now := q.now()
	out := scanevidence.MutationRepairResult{Schema: "1.0", Repairs: []scanevidence.MutationRepair{}}
	for i, x := range r.Resolutions {
		rec := scanevidence.NewMutationRepair(v.ID, r, x, now)
		document, err := json.Marshal(rec)
		if err != nil {
			return scanevidence.MutationRepairResult{}, err
		}
		// The insert trigger re-derives scope and outcome; the update trigger
		// accepts pending->repaired only with this exact record.
		if _, err = tx.ExecContext(ctx, "INSERT INTO scanner_mutation_repairs(intent,generation,job,reconciler,outcome,engine_id,digest,document,created_at) VALUES(?,?,?,?,?,?,?,?,?)", x.Intent, r.Generation, r.Job, v.ID, x.Outcome, x.EngineID, rec.Digest, string(document), rec.Repaired); err != nil {
			return scanevidence.MutationRepairResult{}, ErrConflict
		}
		if res, e := tx.ExecContext(ctx, "UPDATE scanner_mutation_intents SET state='repaired',response_digest=?,response_status=0,result_engine_id=?,completed_at=? WHERE id=? AND generation=? AND state='pending'", rec.Digest, x.EngineID, rec.Repaired, x.Intent, r.Generation); e != nil || affected(res) != 1 {
			return scanevidence.MutationRepairResult{}, ErrConflict
		}
		if err = store.AuditTx(tx, v.Owner, "scanner.mutation_repaired", x.Intent, x.Outcome, map[string]any{"job_id": r.Job, "generation_id": r.Generation, "operation": pending[i].Request.Operation, "reconciler_id": v.ID, "repair_digest": rec.Digest, "membership_digest": r.Membership, "quarantine_digest": r.Fence.Quarantine, "activation_digest": r.Fence.Activation, "cleanup_release_authorized": false}); err != nil {
			return scanevidence.MutationRepairResult{}, err
		}
		out.Repairs = append(out.Repairs, rec)
	}
	if err = tx.Commit(); err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	return out, nil
}

// MutationForAuthorizer lets the original authorizer read one retained intent
// and, when repaired, its repair record, so a quarantined plugin can settle its
// own journal. Found is false only when the generation is closed or released
// and no such intent was ever admitted: a proposed admission that never
// committed can then never commit. It reads; it never settles or audits.
func (q *Queue) MutationForAuthorizer(ctx context.Context, v scanevidence.AuthorizerIdentity, generation, intent string) (scanevidence.MutationIntent, *scanevidence.MutationRepair, bool, error) {
	if !nativeContainerID.MatchString(generation) || !digestPattern.MatchString(intent) {
		return scanevidence.MutationIntent{}, nil, false, ErrInput
	}
	tx, err := q.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return scanevidence.MutationIntent{}, nil, false, err
	}
	defer tx.Rollback()
	var job, state string
	if err = tx.QueryRowContext(ctx, "SELECT job,state FROM scanner_allocation_generations WHERE id=? AND owner=?", generation, v.Owner).Scan(&job, &state); err != nil {
		return scanevidence.MutationIntent{}, nil, false, err
	}
	scope := scanevidence.MutationIntent{Request: scanevidence.MutationRequest{Generation: generation, Job: job}}
	if err = q.completedMutationScopeTx(tx, v, scope); err != nil {
		return scanevidence.MutationIntent{}, nil, false, err
	}
	m, err := readIntent(tx.QueryRowContext(ctx, "SELECT "+intentColumns+" FROM scanner_mutation_intents WHERE id=? AND generation=?", intent, generation))
	if err == sql.ErrNoRows {
		if state != "closed" && state != "released" {
			return scanevidence.MutationIntent{}, nil, false, ErrLease
		}
		return scanevidence.MutationIntent{}, nil, false, nil
	}
	if err != nil {
		return scanevidence.MutationIntent{}, nil, false, err
	}
	if m.State != "repaired" {
		return m, nil, true, nil
	}
	var document string
	if err = tx.QueryRowContext(ctx, "SELECT document FROM scanner_mutation_repairs WHERE intent=? AND digest=?", m.ID, m.Response).Scan(&document); err != nil {
		return scanevidence.MutationIntent{}, nil, false, ErrConflict
	}
	rec, err := scanevidence.DecodeMutationRepair([]byte(document))
	if err != nil || rec.Resolution.Intent != m.ID || rec.Resolution.EngineID != m.EngineID || rec.Generation != generation {
		return scanevidence.MutationIntent{}, nil, false, ErrConflict
	}
	return m, &rec, true, nil
}

// CleanupConfirmationForWorker returns the retained independent cleanup
// confirmation that covered one exact container launched by this worker. The
// worker may use it to close the matching attempt in its own local journal
// after a crash; it is read-only and grants no engine or release authority.
func (q *Queue) CleanupConfirmationForWorker(ctx context.Context, worker, owner, container string) (scanevidence.CleanupConfirmation, error) {
	if !containerID.MatchString(container) {
		return scanevidence.CleanupConfirmation{}, ErrInput
	}
	tx, err := q.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	defer tx.Rollback()
	if err = workerAuthority(tx, worker, owner, q.now().Unix()); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	var job, generation, state, ran, document string
	if err = tx.QueryRowContext(ctx, "SELECT l.job FROM scanner_launches l JOIN scanner_jobs j ON j.id=l.job WHERE j.owner=? AND l.container=?", owner, container).Scan(&job); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT id,state,worker FROM scanner_allocation_generations WHERE job=? AND owner=?", job, owner).Scan(&generation, &state, &ran); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if state != "released" || ran != worker {
		return scanevidence.CleanupConfirmation{}, ErrContextUnbound
	}
	if err = tx.QueryRowContext(ctx, "SELECT document FROM scanner_cleanup_confirmations WHERE job=? AND generation=?", job, generation).Scan(&document); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	var c scanevidence.CleanupConfirmation
	if json.Unmarshal([]byte(document), &c) != nil || c.Request.Job != job || c.Request.Generation != generation || !c.Covers(container) {
		return scanevidence.CleanupConfirmation{}, ErrConflict
	}
	return c, nil
}
