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

// ConfirmCleanup releases one held dispatch after an independent reconciler
// observed every allocation absent from the original engine (ADR 057). The
// controller recomputes membership and the required absences in this
// transaction; the request only proves what the reconciler looked at. A
// confirmation is recorded once per job and replays return it unchanged.
func (q *Queue) ConfirmCleanup(ctx context.Context, v scanevidence.ReconcilerIdentity, r scanevidence.CleanupConfirmationRequest) (scanevidence.CleanupConfirmation, error) {
	if !r.Valid() {
		return scanevidence.CleanupConfirmation{}, ErrInput
	}
	tx, err := q.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	defer tx.Rollback()
	if err = scannerauth.AuthorizeReconcilerTx(tx, v, q.now().Unix()); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	var stored string
	err = tx.QueryRowContext(ctx, "SELECT c.document FROM scanner_cleanup_confirmations c JOIN scanner_jobs j ON j.id=c.job WHERE c.job=? AND j.owner=?", r.Job, v.Owner).Scan(&stored)
	if err == nil {
		var c scanevidence.CleanupConfirmation
		if json.Unmarshal([]byte(stored), &c) != nil || c.Reconciler != v.ID || !sameRequest(c.Request, r) {
			return scanevidence.CleanupConfirmation{}, ErrConflict
		}
		return c, nil
	}
	if err != sql.ErrNoRows {
		return scanevidence.CleanupConfirmation{}, err
	}
	m, err := membershipTx(ctx, tx, v, r.Job, r.Generation)
	if err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if m.JobState == "queued" || m.JobState == "running" || m.Dispatch != "cleanup_required" {
		return scanevidence.CleanupConfirmation{}, ErrContextUnbound
	}
	required, err := scanevidence.RequiredAbsences(m)
	if err != nil {
		return scanevidence.CleanupConfirmation{}, ErrConflict
	}
	b := m.Binding.Document
	if scanevidence.ReconciliationMembershipDigest(m) != r.Membership || b.Engine != r.Engine || b.Namespace != r.Namespace || !sameAbsences(required, r.Absent) {
		return scanevidence.CleanupConfirmation{}, ErrConflict
	}
	if err = ctx.Err(); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if err = scannerauth.AuthorizeReconcilerTx(tx, v, q.now().Unix()); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	c := scanevidence.NewCleanupConfirmation(v.ID, r, q.now())
	document, err := json.Marshal(c)
	if err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO scanner_cleanup_confirmations(job,generation,reconciler,membership_digest,digest,document,created_at) VALUES(?,?,?,?,?,?,?)", r.Job, r.Generation, v.ID, r.Membership, c.Digest, string(document), c.Confirmed); err != nil {
		return scanevidence.CleanupConfirmation{}, ErrConflict
	}
	if res, e := tx.ExecContext(ctx, "UPDATE scanner_allocation_generations SET state='released' WHERE job=? AND id=? AND state='closed'", r.Job, r.Generation); e != nil || affected(res) != 1 {
		return scanevidence.CleanupConfirmation{}, ErrConflict
	}
	if res, e := tx.ExecContext(ctx, "DELETE FROM scanner_dispatch WHERE slot=1 AND job=? AND state='cleanup_required'", r.Job); e != nil || affected(res) != 1 {
		return scanevidence.CleanupConfirmation{}, ErrConflict
	}
	if err = store.AuditTx(tx, v.Owner, "scanner.cleanup_confirmed", r.Job, "released", map[string]any{"generation_id": r.Generation, "reconciler_id": v.ID, "membership_digest": r.Membership, "confirmation_digest": c.Digest, "absent_allocations": len(r.Absent)}); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if err = tx.Commit(); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	return c, nil
}

func affected(r sql.Result) int64 {
	n, e := r.RowsAffected()
	if e != nil {
		return -1
	}
	return n
}

func sameAbsences(a, b []scanevidence.CleanupAbsence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameRequest(a, b scanevidence.CleanupConfirmationRequest) bool {
	return a.Job == b.Job && a.Generation == b.Generation && a.Membership == b.Membership && a.Engine == b.Engine && a.Namespace == b.Namespace && sameAbsences(a.Absent, b.Absent)
}
