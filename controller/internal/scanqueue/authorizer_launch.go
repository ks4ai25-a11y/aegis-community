// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"time"
)

func (q *Queue) MutationBindingForAuthorizer(ctx context.Context, v scanevidence.AuthorizerIdentity) (scanevidence.MutationBindingRecord, error) {
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return scanevidence.MutationBindingRecord{}, e
	}
	defer tx.Rollback()
	if e = scannerauth.AuthorizeAuthorizerTx(tx, v, q.now().Unix()); e != nil {
		return scanevidence.MutationBindingRecord{}, e
	}
	b, e := mutationBindingTx(tx, v.Owner)
	if e != nil {
		return scanevidence.MutationBindingRecord{}, e
	}
	record := scanevidence.MutationBindingRecord{Digest: b.Digest, Document: b}
	record.Document.Digest = ""
	broker, e := q.brokerBindingTx(tx, v.Owner)
	if e != nil {
		return scanevidence.MutationBindingRecord{}, e
	}
	created, e := time.Parse(time.RFC3339Nano, b.Created)
	if e != nil || created.After(q.now()) || !record.Valid(v.Owner, v.ID, v.Engine, v.Registry, v.Policy, b.Namespace) || b.Broker != broker.Digest {
		return scanevidence.MutationBindingRecord{}, ErrLease
	}
	return record, nil
}

// AuthorizerLaunch maps one exact registered name into the selected generation
// in one read transaction. It is not admission and cannot renew any lease.
func (q *Queue) AuthorizerLaunch(ctx context.Context, v scanevidence.AuthorizerIdentity, r scanevidence.AuthorizerLaunchRequest) (scanevidence.AuthorizerLaunch, error) {
	if !r.Valid() {
		return scanevidence.AuthorizerLaunch{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	defer tx.Rollback()
	if e = scannerauth.AuthorizeAuthorizerTx(tx, v, q.now().Unix()); e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT l.job,l.tool FROM scanner_launches l JOIN scanner_jobs j ON j.id=l.job WHERE j.owner=? AND l.container=? LIMIT 2", v.Owner, r.Container)
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	var job, tool string
	count := 0
	for rows.Next() {
		if e = rows.Scan(&job, &tool); e != nil {
			rows.Close()
			return scanevidence.AuthorizerLaunch{}, e
		}
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	if count != 1 {
		return scanevidence.AuthorizerLaunch{}, sql.ErrNoRows
	}
	g, b, j, e := q.generationTx(tx, v, job, r.Operation == "remove")
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	launch, e := launchTx(tx, j, tool)
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	workspace, e := workspaceTx(tx, j, tool)
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	if e = matchWorkspaceTx(tx, j, launch.Document.Plan, launch.Document.Created); e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	record := scanevidence.MutationBindingRecord{Digest: b.Digest, Document: b}
	record.Document.Digest = ""
	d := scanevidence.AuthorizerLaunch{Schema: "1.0", Challenge: r.Challenge, Operation: r.Operation, Binding: record, Generation: g, Launch: launch, Workspace: workspace, Guards: q.Guards, Observed: q.now().UTC().Format(time.RFC3339Nano), MetadataOnly: true}
	if e = tx.QueryRowContext(ctx, "SELECT lease_until FROM scanner_dispatch WHERE job=?", job).Scan(&d.LeaseUntil); e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	if !d.Valid(v, b.Namespace, q.LockDigest, r, q.now()) {
		return scanevidence.AuthorizerLaunch{}, ErrConflict
	}
	if e = ctx.Err(); e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	return d, nil
}
