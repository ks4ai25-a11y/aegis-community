// SPDX-License-Identifier: Apache-2.0
package scannerauth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"regexp"
	"time"
)

var authorizerHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func authorizerTokenHash(token string) string {
	return domain.Hash([]byte("aegis-scanner-engine-authorizer-v1\x00" + token))
}
func (r *Registry) enrollAuthorizer(owner, id string, minutes int, engine, registry, policy string, issue func(string) error) (scanevidence.AuthorizerIdentity, error) {
	if !workerID.MatchString(id) || owner == "" || len(owner) > 128 || minutes < 1 || minutes > 1440 || !authorizerHash.MatchString(engine) || !authorizerHash.MatchString(registry) || !authorizerHash.MatchString(policy) || issue == nil {
		return scanevidence.AuthorizerIdentity{}, ErrInput
	}
	bytes := make([]byte, 32)
	if _, e := rand.Read(bytes); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	token := hex.EncodeToString(bytes)
	tx, e := r.S.DB.Begin()
	if e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	defer tx.Rollback()
	var bound string
	if e = tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&bound); e != nil || bound != owner {
		return scanevidence.AuthorizerIdentity{}, ErrDenied
	}
	var repos, total, active, existing int
	if e = tx.QueryRow("SELECT count(*) FROM repositories WHERE owner=?", owner).Scan(&repos); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	if repos == 0 {
		return scanevidence.AuthorizerIdentity{}, ErrDenied
	}
	now := r.now().UTC()
	if e = tx.QueryRow("SELECT count(*) FROM scanner_authorizers WHERE id=?", id).Scan(&existing); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	if e = tx.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN owner=? AND state='active' AND expires>? THEN 1 ELSE 0 END),0) FROM scanner_authorizers", owner, now.Unix()).Scan(&total, &active); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	if existing != 0 || total >= 100 || active >= 1 {
		return scanevidence.AuthorizerIdentity{}, ErrConflict
	}
	v := scanevidence.AuthorizerIdentity{Schema: "1.0", Role: scanevidence.ScannerAuthorizerRole, ID: id, Owner: owner, Engine: engine, Registry: registry, Policy: policy, State: "active", Created: now.Format(time.RFC3339Nano), Expires: now.Add(time.Duration(minutes) * time.Minute).Format(time.RFC3339)}
	if _, e = tx.Exec("INSERT INTO scanner_authorizers VALUES(?,?,?,'active',?,?,?,?,?)", id, owner, authorizerTokenHash(token), engine, registry, policy, now.Add(time.Duration(minutes)*time.Minute).Unix(), v.Created); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.authorizer_enroll", id, "active", map[string]any{"role": v.Role, "engine_digest": engine, "registry_digest": registry, "policy_digest": policy, "expires_at": v.Expires}); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	if e = issue(token); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	return v, nil
}
func (r *Registry) AuthenticateAuthorizer(token string) (scanevidence.AuthorizerIdentity, error) {
	if !tokenFormat.MatchString(token) {
		return scanevidence.AuthorizerIdentity{}, ErrDenied
	}
	v := scanevidence.AuthorizerIdentity{Schema: "1.0", Role: scanevidence.ScannerAuthorizerRole}
	var expires int64
	e := r.S.DB.QueryRow("SELECT id,owner,state,engine_digest,registry_digest,policy_digest,expires,created_at FROM scanner_authorizers WHERE token_hash=? AND state='active' AND expires>?", authorizerTokenHash(token), r.now().Unix()).Scan(&v.ID, &v.Owner, &v.State, &v.Engine, &v.Registry, &v.Policy, &expires, &v.Created)
	if e == sql.ErrNoRows {
		return scanevidence.AuthorizerIdentity{}, ErrDenied
	}
	if e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	v.Expires = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	if scanevidence.ValidateAuthorizerIdentity(v, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, r.now()) != nil {
		return scanevidence.AuthorizerIdentity{}, ErrDenied
	}
	return v, nil
}

// AuthorizeAuthorizerTx rechecks the immutable enrollment in the caller transaction.
// It confers no mutation or cleanup authority without that operation's ledger checks.
func AuthorizeAuthorizerTx(tx *sql.Tx, v scanevidence.AuthorizerIdentity, now int64) error {
	if scanevidence.ValidateAuthorizerIdentity(v, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, time.Unix(now, 0)) != nil {
		return ErrDenied
	}
	var n int
	e := tx.QueryRow("SELECT count(*) FROM scanner_authorizers WHERE id=? AND owner=? AND engine_digest=? AND registry_digest=? AND policy_digest=? AND state='active' AND expires>?", v.ID, v.Owner, v.Engine, v.Registry, v.Policy, now).Scan(&n)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDenied
	}
	return nil
}
func (r *Registry) RevokeAuthorizer(owner, id string) error {
	if owner == "" || !workerID.MatchString(id) {
		return ErrInput
	}
	tx, e := r.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state string
	e = tx.QueryRow("SELECT state FROM scanner_authorizers WHERE id=? AND owner=?", id, owner).Scan(&state)
	if e == sql.ErrNoRows {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	if state == "revoked" {
		// An older controller could revoke enrollment before selected-binding
		// revocation was integrated. Explicit repeated revocation must still
		// withdraw that derived authority, preserving its history and holds.
		result, e := tx.Exec("UPDATE scanner_mutation_bindings SET state='revoked' WHERE authorizer=? AND owner=? AND state='active'", id, owner)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n > 0 {
			if e = store.AuditTx(tx, owner, "scanner.authorizer_binding_revoke", id, "revoked", map[string]any{"cleanup_admission_released": false}); e != nil {
				return e
			}
		}
		return tx.Commit()
	}
	if state != "active" {
		return ErrDenied
	}
	if _, e = tx.Exec("UPDATE scanner_authorizers SET state='revoked' WHERE id=? AND owner=?", id, owner); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE scanner_mutation_bindings SET state='revoked' WHERE authorizer=? AND owner=? AND state='active'", id, owner); e != nil {
		return e
	}
	if e = store.AuditTx(tx, owner, "scanner.authorizer_revoke", id, "revoked", map[string]any{"role": scanevidence.ScannerAuthorizerRole, "cleanup_admission_released": false}); e != nil {
		return e
	}
	return tx.Commit()
}
