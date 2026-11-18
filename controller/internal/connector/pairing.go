// SPDX-License-Identifier: BUSL-1.1
package connector

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
)

const PairedPrefix = "aegis_dp_"
const PairedScope = "desktop_handoff_v1"
const pairingLifetime = 5 * time.Minute

var (
	ErrPairingUnavailable = errors.New("pairing unavailable")
	ErrPairingPending     = errors.New("owner confirmation pending")
	ErrPairingInput       = errors.New("invalid pairing request")
	ErrPairingCapacity    = errors.New("pairing capacity reached")
	pairedTokenShape      = regexp.MustCompile(`^aegis_dp_[0-9a-f]{64}$`)
	connectorIDShape      = regexp.MustCompile(`^[0-9a-f-]{36}$`)
)

type Pairing struct {
	ID          string `json:"pairing_id"`
	Name        string `json:"name"`
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Expires     int64  `json:"expires_unix"`
	Minutes     int    `json:"lifetime_minutes"`
	AllowDraft  bool   `json:"allow_analysis_draft"`
}

func (r *Registry) Invite(ctx context.Context, owner, name string, minutes int, draft bool) (Pairing, string, error) {
	if !nameShape.MatchString(name) || (minutes != 15 && minutes != 30 && minutes != 60) {
		return Pairing{}, "", ErrPairingInput
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return Pairing{}, "", err
	}
	code := hex.EncodeToString(secret[:])
	now := r.now()
	p := Pairing{ID: domain.ID(), Name: name, State: "new", Expires: now.Add(pairingLifetime).Unix(), Minutes: minutes, AllowDraft: draft}
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return Pairing{}, "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM desktop_pairing_invites WHERE expires<=?", now.Unix()); err != nil {
		return Pairing{}, "", err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM desktop_pairing_invites").Scan(&count); err != nil {
		return Pairing{}, "", err
	}
	if count >= 64 {
		return Pairing{}, "", ErrPairingCapacity
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO desktop_pairing_invites(id,owner,name,invite_hash,expires,minutes,allow_draft,state)
 VALUES(?,?,?,?,?,?,?,'new')`, p.ID, owner, name, domain.Hash([]byte(code)), p.Expires, minutes, draft); err != nil {
		return Pairing{}, "", err
	}
	if err = store.AuditTx(tx, owner, "desktop.pairing_created", p.ID, "new", map[string]any{"minutes": minutes, "allow_analysis_draft": draft}); err != nil {
		return Pairing{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return Pairing{}, "", err
	}
	return p, code, nil
}

func (r *Registry) Pairing(ctx context.Context, owner, id string) (Pairing, error) {
	p := Pairing{ID: id}
	err := r.S.DB.QueryRowContext(ctx, `SELECT name,state,fingerprint,expires,minutes,allow_draft FROM desktop_pairing_invites WHERE id=? AND owner=?`, id, owner).
		Scan(&p.Name, &p.State, &p.Fingerprint, &p.Expires, &p.Minutes, &p.AllowDraft)
	if errors.Is(err, sql.ErrNoRows) {
		return Pairing{}, ErrPairingUnavailable
	}
	if err == nil && p.Expires <= r.now().Unix() && p.State != "redeemed" && p.State != "cancelled" {
		p.State = "expired"
	}
	return p, err
}

func sameSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// Claim binds both the private proof and a device-generated token hash. The
// bridge independently derives its fingerprint from this transcript.
func (r *Registry) ClaimPairing(ctx context.Context, id, code, proof, tokenDigest string) error {
	if !connectorIDShape.MatchString(id) || !handoffShape.MatchString(code) || !handoffShape.MatchString(proof) || !digestShape.MatchString(tokenDigest) {
		return ErrPairingUnavailable
	}
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner, state, secret, originalProof, originalToken string
	now := r.now().Unix()
	err = tx.QueryRowContext(ctx, `SELECT owner,state,invite_hash,proof_hash,token_hash FROM desktop_pairing_invites WHERE id=? AND expires>?`, id, now).
		Scan(&owner, &state, &secret, &originalProof, &originalToken)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPairingUnavailable
	}
	if err != nil {
		return err
	}
	proofHash := domain.Hash([]byte(proof))
	if !sameSecret(secret, domain.Hash([]byte(code))) {
		return ErrPairingUnavailable
	}
	if state == "claimed" && sameSecret(originalProof, proofHash) && sameSecret(originalToken, tokenDigest) {
		return tx.Commit()
	}
	if state != "new" {
		return ErrPairingUnavailable
	}
	fingerprint := domain.Hash([]byte("aegis-pairing-v1\n" + id + "\n" + proof + "\n" + tokenDigest))[7:27]
	if _, err = tx.ExecContext(ctx, `UPDATE desktop_pairing_invites SET state='claimed',proof_hash=?,fingerprint=?,token_hash=? WHERE id=?`, proofHash, fingerprint, tokenDigest, id); err != nil {
		return err
	}
	if err = store.AuditTx(tx, owner, "desktop.pairing_claimed", id, "claimed", nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Registry) DecidePairing(ctx context.Context, owner, id, fingerprint string, approve bool) error {
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var res sql.Result
	state := "cancelled"
	if approve {
		state = "approved"
		res, err = tx.ExecContext(ctx, `UPDATE desktop_pairing_invites SET state='approved'
   WHERE id=? AND owner=? AND state='claimed' AND fingerprint=? AND expires>?`, id, owner, strings.ToLower(strings.TrimSpace(fingerprint)), r.now().Unix())
	} else {
		res, err = tx.ExecContext(ctx, `UPDATE desktop_pairing_invites SET state='cancelled'
  WHERE id=? AND owner=? AND state IN ('new','claimed','approved')`, id, owner)
	}
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPairingUnavailable
	}
	if err = store.AuditTx(tx, owner, "desktop.pairing_decided", id, state, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Registry) RedeemPairing(ctx context.Context, id, proof string) (Credential, error) {
	if !connectorIDShape.MatchString(id) || !handoffShape.MatchString(proof) {
		return Credential{}, ErrPairingUnavailable
	}
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return Credential{}, err
	}
	defer tx.Rollback()
	now := r.now()
	c := Credential{ID: id, Scope: PairedScope, State: "active"}
	var owner, state, storedProof, tokenHash, fingerprint string
	var minutes int
	var draft bool
	err = tx.QueryRowContext(ctx, `SELECT owner,name,state,proof_hash,token_hash,fingerprint,minutes,allow_draft FROM desktop_pairing_invites WHERE id=? AND expires>?`, id, now.Unix()).
		Scan(&owner, &c.Name, &state, &storedProof, &tokenHash, &fingerprint, &minutes, &draft)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrPairingUnavailable
	}
	if err != nil {
		return Credential{}, err
	}
	c.Fingerprint, c.AllowDraft = fingerprint, draft
	if !sameSecret(storedProof, domain.Hash([]byte(proof))) {
		return Credential{}, ErrPairingUnavailable
	}
	if state == "claimed" {
		return Credential{}, ErrPairingPending
	}
	if state == "redeemed" {
		err = tx.QueryRowContext(ctx, `SELECT created_at,expires FROM connector_credentials WHERE id=? AND state='active' AND expires>?`, id, now.Unix()).Scan(&c.Created, &c.Expires)
		if errors.Is(err, sql.ErrNoRows) {
			return Credential{}, ErrPairingUnavailable
		}
		if err != nil {
			return Credential{}, err
		}
		return c, tx.Commit()
	}
	if state != "approved" {
		return Credential{}, ErrPairingUnavailable
	}
	var retained int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM desktop_paired_connectors").Scan(&retained); err != nil {
		return Credential{}, err
	}
	if retained >= 512 {
		return Credential{}, ErrPairingCapacity
	}
	c.Created = now.UTC().Format(time.RFC3339Nano)
	c.Expires = now.Add(time.Duration(minutes) * time.Minute).Unix()
	if _, err = tx.ExecContext(ctx, `INSERT INTO connector_credentials(id,owner,name,token_hash,scope,state,created_at,expires)
 VALUES(?,?,?,?,?,'active',?,?)`, id, owner, c.Name, tokenHash, Scope, c.Created, c.Expires); err != nil {
		return Credential{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO desktop_paired_connectors VALUES(?,?,?)", id, draft, fingerprint); err != nil {
		return Credential{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE desktop_pairing_invites SET state='redeemed' WHERE id=?", id); err != nil {
		return Credential{}, err
	}
	if err = store.AuditTx(tx, owner, "desktop.pairing_redeemed", id, "active", map[string]any{"expires_unix": c.Expires, "allow_analysis_draft": draft}); err != nil {
		return Credential{}, err
	}
	return c, tx.Commit()
}

func (r *Registry) PairedRoute(ctx context.Context, id, method, path string) bool {
	var draft bool
	if r.S.DB.QueryRowContext(ctx, "SELECT allow_draft FROM desktop_paired_connectors WHERE id=?", id).Scan(&draft) != nil {
		return false
	}
	if method == "GET" && (path == "/desktop/status" || strings.HasPrefix(path, "/desktop/handoffs/")) {
		return true
	}
	return draft && ((method == "POST" && path == "/desktop/drafts") || (method == "GET" && strings.HasPrefix(path, "/desktop/drafts/")))
}
