// SPDX-License-Identifier: Apache-2.0
package scannerauth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

func reconcilerTokenHash(token string) string {
	return domain.Hash([]byte("aegis-scanner-engine-reconciler-v1\x00" + token))
}

type reconcilerQuery interface {
	QueryRow(string, ...any) *sql.Row
}

func reconcilerBinding(q reconcilerQuery, owner, binding string) (scanevidence.MutationBindingRecord, error) {
	var b scanevidence.MutationBindingRecord
	d := &b.Document
	err := q.QueryRow("SELECT digest,owner,authorizer,engine_digest,registry_digest,policy_digest,namespace_digest,broker_binding_digest,created_at FROM scanner_mutation_bindings WHERE digest=? AND owner=?", binding, owner).Scan(&b.Digest, &d.Owner, &d.Authorizer, &d.Engine, &d.Registry, &d.Policy, &d.Namespace, &d.Broker, &d.Created)
	if err != nil {
		return b, err
	}
	if !b.Valid(owner, d.Authorizer, d.Engine, d.Registry, d.Policy, d.Namespace) {
		return scanevidence.MutationBindingRecord{}, ErrDenied
	}
	var original int
	if q.QueryRow("SELECT count(*) FROM scanner_authorizers WHERE id=? AND owner=? AND engine_digest=? AND registry_digest=? AND policy_digest=?", d.Authorizer, owner, d.Engine, d.Registry, d.Policy).Scan(&original) != nil || original != 1 {
		return scanevidence.MutationBindingRecord{}, ErrDenied
	}
	return b, nil
}

func readReconciler(q reconcilerQuery, id, owner string, now time.Time) (scanevidence.ReconcilerIdentity, error) {
	v := scanevidence.ReconcilerIdentity{Schema: "1.0", Role: scanevidence.ScannerReconcilerRole}
	var expires int64
	err := q.QueryRow("SELECT id,owner,binding_digest,capability,state,expires,created_at FROM scanner_reconcilers WHERE id=? AND owner=? AND state='active' AND expires>?", id, owner, now.Unix()).Scan(&v.ID, &v.Owner, &v.Binding, &v.Capability, &v.State, &expires, &v.Created)
	if err != nil {
		return v, err
	}
	b, err := reconcilerBinding(q, v.Owner, v.Binding)
	if err != nil {
		return v, err
	}
	v.Engine, v.Registry, v.Policy, v.Namespace = b.Document.Engine, b.Document.Registry, b.Document.Policy, b.Document.Namespace
	v.Expires = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	if !v.Valid(now) {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	return v, nil
}

func (r *Registry) enrollReconciler(owner, id string, minutes int, binding string, issue func(string) error) (scanevidence.ReconcilerIdentity, error) {
	if owner == "" || len(owner) > 128 || !workerID.MatchString(id) || minutes < 1 || minutes > 1440 || !authorizerHash.MatchString(binding) || issue == nil {
		return scanevidence.ReconcilerIdentity{}, ErrInput
	}
	tx, err := r.S.DB.Begin()
	if err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	defer tx.Rollback()
	var selectedOwner string
	if tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&selectedOwner) != nil || selectedOwner != owner {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	b, err := reconcilerBinding(tx, owner, binding)
	if err != nil {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	now := r.now().UTC()
	boundAt, err := time.Parse(time.RFC3339Nano, b.Document.Created)
	if err != nil || boundAt.After(now) {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	var repos, total, active, existing int
	if tx.QueryRow("SELECT count(*) FROM repositories WHERE owner=?", owner).Scan(&repos) != nil || repos == 0 {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	if err = tx.QueryRow("SELECT count(*) FROM scanner_reconcilers WHERE id=?", id).Scan(&existing); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	if err = tx.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN binding_digest=? AND state='active' AND expires>? THEN 1 ELSE 0 END),0) FROM scanner_reconcilers", binding, now.Unix()).Scan(&total, &active); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	if existing != 0 || total >= 100 || active >= 1 {
		return scanevidence.ReconcilerIdentity{}, ErrConflict
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	token := hex.EncodeToString(random[:])
	created, expires := now.Format(time.RFC3339Nano), now.Add(time.Duration(minutes)*time.Minute).Unix()
	if _, err = tx.Exec("INSERT INTO scanner_reconcilers VALUES(?,?,?,?,?,'active',?,?)", id, owner, reconcilerTokenHash(token), binding, scanevidence.ConfirmFencedCleanup, expires, created); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	if err = store.AuditTx(tx, owner, "scanner.reconciler_enroll", id, "active", map[string]any{"binding_digest": binding, "capability": scanevidence.ConfirmFencedCleanup, "cleanup_confirmed": false}); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	v, err := readReconciler(tx, id, owner, now)
	if err != nil {
		return v, err
	}
	if err = issue(token); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	if err = tx.Commit(); err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	return v, nil
}

func (r *Registry) AuthenticateReconciler(token string) (scanevidence.ReconcilerIdentity, error) {
	if !tokenFormat.MatchString(token) {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	// Keep both reads in one transaction, including retained binding validation.
	tx, err := r.S.DB.Begin()
	if err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	defer tx.Rollback()
	var id, owner string
	if tx.QueryRow("SELECT id,owner FROM scanner_reconcilers WHERE token_hash=? AND state='active' AND expires>?", reconcilerTokenHash(token), r.now().Unix()).Scan(&id, &owner) != nil {
		return scanevidence.ReconcilerIdentity{}, ErrDenied
	}
	return readReconciler(tx, id, owner, r.now())
}

func AuthorizeReconcilerTx(tx *sql.Tx, v scanevidence.ReconcilerIdentity, now int64) error {
	if !v.Valid(time.Unix(now, 0)) {
		return ErrDenied
	}
	actual, err := readReconciler(tx, v.ID, v.Owner, time.Unix(now, 0))
	if err != nil || actual != v {
		return ErrDenied
	}
	return nil
}

func (r *Registry) RevokeReconciler(owner, id string) error {
	if owner == "" || len(owner) > 128 || !workerID.MatchString(id) {
		return ErrInput
	}
	tx, err := r.S.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if tx.QueryRow("SELECT state FROM scanner_reconcilers WHERE id=? AND owner=?", id, owner).Scan(&state) != nil {
		return ErrDenied
	}
	if state == "revoked" {
		return nil
	}
	if _, err = tx.Exec("UPDATE scanner_reconcilers SET state='revoked' WHERE id=? AND owner=? AND state='active'", id, owner); err != nil {
		return err
	}
	if err = store.AuditTx(tx, owner, "scanner.reconciler_revoke", id, "revoked", map[string]any{"cleanup_confirmed": false}); err != nil {
		return err
	}
	return tx.Commit()
}
