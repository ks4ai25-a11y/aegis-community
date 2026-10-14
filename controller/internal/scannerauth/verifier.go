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

var verifierHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func verifierTokenHash(token string) string {
	return domain.Hash([]byte("aegis-scanner-cleanup-observer-v1\x00" + token))
}
func (r *Registry) enrollVerifier(owner, id string, minutes int, engine, registry string, issue func(string) error) (scanevidence.VerifierIdentity, error) {
	if !workerID.MatchString(id) || owner == "" || len(owner) > 128 || minutes < 1 || minutes > 1440 || !verifierHash.MatchString(engine) || !verifierHash.MatchString(registry) || issue == nil {
		return scanevidence.VerifierIdentity{}, ErrInput
	}
	bytes := make([]byte, 32)
	if _, e := rand.Read(bytes); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	token := hex.EncodeToString(bytes)
	tx, e := r.S.DB.Begin()
	if e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	defer tx.Rollback()
	var bound string
	if e = tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&bound); e != nil || bound != owner {
		return scanevidence.VerifierIdentity{}, ErrDenied
	}
	var repos, total, active, existing int
	if e = tx.QueryRow("SELECT count(*) FROM repositories WHERE owner=?", owner).Scan(&repos); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if repos == 0 {
		return scanevidence.VerifierIdentity{}, ErrDenied
	}
	now := r.now().UTC()
	if e = tx.QueryRow("SELECT count(*) FROM scanner_verifiers WHERE id=?", id).Scan(&existing); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if e = tx.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN owner=? AND state='active' AND expires>? THEN 1 ELSE 0 END),0) FROM scanner_verifiers", owner, now.Unix()).Scan(&total, &active); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if existing != 0 || total >= 100 || active >= 4 {
		return scanevidence.VerifierIdentity{}, ErrConflict
	}
	v := scanevidence.VerifierIdentity{Schema: "1.0", Role: scanevidence.CleanupObserverRole, ID: id, Owner: owner, Engine: engine, Registry: registry, State: "active", Created: now.Format(time.RFC3339Nano), Expires: now.Add(time.Duration(minutes) * time.Minute).Format(time.RFC3339)}
	if _, e = tx.Exec("INSERT INTO scanner_verifiers VALUES(?,?,?,'active',?,?,?,?)", id, owner, verifierTokenHash(token), engine, registry, now.Add(time.Duration(minutes)*time.Minute).Unix(), v.Created); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.verifier_enroll", id, "active", map[string]any{"role": v.Role, "engine_digest": engine, "registry_digest": registry, "expires_at": v.Expires}); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if e = issue(token); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	return v, nil
}
func (r *Registry) AuthenticateVerifier(token string) (scanevidence.VerifierIdentity, error) {
	if !tokenFormat.MatchString(token) {
		return scanevidence.VerifierIdentity{}, ErrDenied
	}
	v := scanevidence.VerifierIdentity{Schema: "1.0", Role: scanevidence.CleanupObserverRole}
	var expires int64
	e := r.S.DB.QueryRow("SELECT id,owner,state,engine_digest,registry_digest,expires,created_at FROM scanner_verifiers WHERE token_hash=? AND state='active' AND expires>?", verifierTokenHash(token), r.now().Unix()).Scan(&v.ID, &v.Owner, &v.State, &v.Engine, &v.Registry, &expires, &v.Created)
	if e == sql.ErrNoRows {
		return scanevidence.VerifierIdentity{}, ErrDenied
	}
	if e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	v.Expires = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	if !workerID.MatchString(v.ID) || !verifierHash.MatchString(v.Engine) || !verifierHash.MatchString(v.Registry) {
		return scanevidence.VerifierIdentity{}, ErrDenied
	}
	return v, nil
}

// AuthorizeVerifierTx closes the authenticate/revoke gap for context reads.
func AuthorizeVerifierTx(tx *sql.Tx, v scanevidence.VerifierIdentity, now int64) error {
	if v.Schema != "1.0" || v.Role != scanevidence.CleanupObserverRole || !workerID.MatchString(v.ID) || v.Owner == "" || !verifierHash.MatchString(v.Engine) || !verifierHash.MatchString(v.Registry) {
		return ErrDenied
	}
	var n int
	e := tx.QueryRow("SELECT count(*) FROM scanner_verifiers WHERE id=? AND owner=? AND engine_digest=? AND registry_digest=? AND state='active' AND expires>?", v.ID, v.Owner, v.Engine, v.Registry, now).Scan(&n)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDenied
	}
	return nil
}
func (r *Registry) RevokeVerifier(owner, id string) error {
	if owner == "" || !workerID.MatchString(id) {
		return ErrInput
	}
	tx, e := r.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state string
	e = tx.QueryRow("SELECT state FROM scanner_verifiers WHERE id=? AND owner=?", id, owner).Scan(&state)
	if e == sql.ErrNoRows {
		return ErrDenied
	}
	if e != nil {
		return e
	}
	if state == "revoked" {
		return nil
	}
	if state != "active" {
		return ErrDenied
	}
	if _, e = tx.Exec("UPDATE scanner_verifiers SET state='revoked' WHERE id=? AND owner=?", id, owner); e != nil {
		return e
	}
	if e = store.AuditTx(tx, owner, "scanner.verifier_revoke", id, "revoked", map[string]any{"role": scanevidence.CleanupObserverRole, "cleanup_admission_released": false}); e != nil {
		return e
	}
	return tx.Commit()
}
