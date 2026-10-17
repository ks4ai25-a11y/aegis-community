// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
)

// ReconciliationSnapshot reads complete retained membership, not a worker
// supplied subset. Closed admission can still acquire a separately admitted
// removal, so final release must compare the stable membership digest again.
// This operation never mutates, renews, settles or releases any allocation.
func (q *Queue) ReconciliationSnapshot(ctx context.Context, v scanevidence.ReconcilerIdentity, r scanevidence.ReconciliationRequest) (scanevidence.ReconciliationSnapshot, error) {
	if !r.Valid() {
		return scanevidence.ReconciliationSnapshot{}, ErrInput
	}
	tx, err := q.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	defer tx.Rollback()
	if err = scannerauth.AuthorizeReconcilerTx(tx, v, q.now().Unix()); err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	j, err := read(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", r.Job, v.Owner))
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	m := scanevidence.ReconciliationMembership{Owner: j.Owner, Job: j.ID, Request: j.RequestDigest, App: j.Input.App, Repository: j.Input.Repository, Map: j.Input.MapDigest, Lock: j.LockDigest, Duration: j.Input.Duration, Created: j.Created, JobState: j.State, Cancelled: j.CancelRequested, Tools: append([]string{}, j.Input.Tools...), Workspaces: []scanevidence.WorkspaceRecord{}, Launches: []scanevidence.LaunchRecord{}, Mutations: []scanevidence.MutationIntent{}}
	b := &m.Binding.Document
	err = tx.QueryRowContext(ctx, "SELECT digest,owner,authorizer,engine_digest,registry_digest,policy_digest,namespace_digest,broker_binding_digest,created_at FROM scanner_mutation_bindings WHERE digest=? AND owner=?", v.Binding, v.Owner).Scan(&m.Binding.Digest, &b.Owner, &b.Authorizer, &b.Engine, &b.Registry, &b.Policy, &b.Namespace, &b.Broker, &b.Created)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	g := &m.Generation
	var leaseHash string
	err = tx.QueryRowContext(ctx, "SELECT id,job,binding_digest,state,deadline,worker,lease_hash,guard_digest FROM scanner_allocation_generations WHERE job=? AND owner=? AND id=? AND binding_digest=?", j.ID, v.Owner, r.Generation, v.Binding).Scan(&g.ID, &g.Job, &g.Binding, &g.State, &g.Deadline, &m.Worker, &leaseHash, &m.GuardSet)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	var worker, dispatchHash, guard string
	var deadline int64
	var launchProtocol, workspaceProtocol int
	err = tx.QueryRowContext(ctx, "SELECT worker,token_hash,deadline,state,lease_until,guard_set_digest,launch_protocol,workspace_protocol FROM scanner_dispatch WHERE job=?", j.ID).Scan(&worker, &dispatchHash, &deadline, &m.Dispatch, &m.LeaseUntil, &guard, &launchProtocol, &workspaceProtocol)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	if g.State != "closed" || worker != m.Worker || dispatchHash != leaseHash || deadline != g.Deadline || guard != m.GuardSet || launchProtocol != 1 || workspaceProtocol != 1 || !digestPattern.MatchString(leaseHash) {
		return scanevidence.ReconciliationSnapshot{}, ErrContextUnbound
	}
	m.Fingerprint = domain.Digest(struct {
		Domain, Job, Worker, LeaseHash, Guard string
		Deadline                              int64
		LaunchProtocol, WorkspaceProtocol     int
	}{"aegis-scanner-reconciliation-dispatch-v1", j.ID, worker, leaseHash, guard, deadline, launchProtocol, workspaceProtocol})

	// Include orphaned/inconsistent records too; validation must reject them,
	// rather than hide an obligation by filtering only one of its foreign keys.
	rows, err := tx.QueryContext(ctx, "SELECT tool FROM scanner_workspaces WHERE job=? UNION SELECT tool FROM scanner_launches WHERE job=? UNION SELECT tool FROM scanner_mutation_intents WHERE job=? OR generation=? ORDER BY tool", j.ID, j.ID, j.ID, g.ID)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	var tools []string
	for rows.Next() {
		var tool string
		if rows.Scan(&tool) != nil || len(tools) >= 6 {
			rows.Close()
			return scanevidence.ReconciliationSnapshot{}, ErrConflict
		}
		tools = append(tools, tool)
	}
	readErr := rows.Err()
	if rows.Close() != nil || readErr != nil {
		return scanevidence.ReconciliationSnapshot{}, ErrConflict
	}
	selected := map[string]bool{}
	for _, tool := range m.Tools {
		selected[tool] = true
	}
	for _, tool := range tools {
		if !selected[tool] {
			return scanevidence.ReconciliationSnapshot{}, ErrConflict
		}
		w, err := workspaceTx(tx, j, tool)
		if err != nil {
			return scanevidence.ReconciliationSnapshot{}, ErrConflict
		}
		m.Workspaces = append(m.Workspaces, w)
		l, err := launchTx(tx, j, tool)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil || matchWorkspaceTx(tx, j, l.Document.Plan, l.Document.Created) != nil {
			return scanevidence.ReconciliationSnapshot{}, ErrConflict
		}
		m.Launches = append(m.Launches, l)
	}
	rows, err = tx.QueryContext(ctx, "SELECT "+intentColumns+" FROM scanner_mutation_intents WHERE job=? OR generation=? ORDER BY id", j.ID, g.ID)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	for rows.Next() {
		intent, err := readIntent(rows)
		if err != nil || len(m.Mutations) >= 18 {
			rows.Close()
			return scanevidence.ReconciliationSnapshot{}, ErrConflict
		}
		m.Mutations = append(m.Mutations, intent)
	}
	readErr = rows.Err()
	if rows.Close() != nil || readErr != nil {
		return scanevidence.ReconciliationSnapshot{}, ErrConflict
	}
	if err = ctx.Err(); err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	if err = scannerauth.AuthorizeReconcilerTx(tx, v, q.now().Unix()); err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	out, err := scanevidence.NewReconciliationSnapshot(m, v, r, q.now())
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, ErrConflict
	}
	return out, nil
}
