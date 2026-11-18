// SPDX-License-Identifier: BUSL-1.1
package connector

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
)

var ErrRenewalUnavailable = errors.New("desktop renewal unavailable")
var ErrRenewalConflict = errors.New("desktop renewal does not match the approved rotation")

type RenewalApproval struct {
	ID    string `json:"connector_id"`
	Until int64  `json:"approval_expires_unix"`
}

type RenewalReceipt struct {
	ID      string `json:"connector_id"`
	Expires int64  `json:"expires_unix"`
}

func pairedCredentialHash(token string) string {
	return domain.Hash([]byte("aegis-paired-token-v1\x00" + token))
}

func (r *Registry) ApproveRenewal(ctx context.Context, owner, id string) (RenewalApproval, error) {
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return RenewalApproval{}, err
	}
	defer tx.Rollback()
	now := r.now().Unix()
	var hash string
	var oldExpiry int64
	err = tx.QueryRowContext(ctx, `SELECT c.token_hash,c.expires FROM connector_credentials c JOIN desktop_paired_connectors p ON p.id=c.id
  WHERE c.id=? AND c.owner=? AND c.state='active' AND c.expires>?`, id, owner, now).Scan(&hash, &oldExpiry)
	if errors.Is(err, sql.ErrNoRows) {
		return RenewalApproval{}, ErrRenewalUnavailable
	}
	if err != nil {
		return RenewalApproval{}, err
	}
	var until int64
	err = tx.QueryRowContext(ctx, `SELECT approved_until FROM desktop_renewals WHERE old_hash=? AND state='approved' AND approved_until>?`, hash, now).Scan(&until)
	if err == nil {
		return RenewalApproval{ID: id, Until: until}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return RenewalApproval{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM desktop_renewals WHERE state='approved' AND approved_until<=?`, now); err != nil {
		return RenewalApproval{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM desktop_renewals").Scan(&count); err != nil {
		return RenewalApproval{}, err
	}
	if count >= 4096 {
		return RenewalApproval{}, ErrPairingCapacity
	}
	until = min(oldExpiry, now+300)
	if _, err = tx.ExecContext(ctx, `INSERT INTO desktop_renewals(old_hash,connector,old_expires,approved_until,state)
 VALUES(?,?,?,?,'approved')`, hash, id, oldExpiry, until); err != nil {
		return RenewalApproval{}, err
	}
	if err = store.AuditTx(tx, owner, "desktop.renewal_approved", id, "approved", map[string]int64{"approval_expires_unix": until}); err != nil {
		return RenewalApproval{}, err
	}
	return RenewalApproval{ID: id, Until: until}, tx.Commit()
}

// Renew rotates a paired credential without granting any new connector scope.
// The old token can recover only the matching receipt during the approval window.
func (r *Registry) Renew(ctx context.Context, header, newHash string) (RenewalReceipt, error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || !pairedTokenShape.MatchString(token) || !digestShape.MatchString(newHash) {
		return RenewalReceipt{}, ErrRenewalUnavailable
	}
	oldHash := pairedCredentialHash(token)
	if oldHash == newHash {
		return RenewalReceipt{}, ErrRenewalConflict
	}
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return RenewalReceipt{}, err
	}
	defer tx.Rollback()
	now := r.now().Unix()
	var id, owner, state, liveHash, recordedHash string
	var oldExpiry, liveExpiry, newExpiry int64
	err = tx.QueryRowContext(ctx, `SELECT x.connector,c.owner,x.state,c.token_hash,c.expires,x.old_expires,x.new_hash,x.new_expires
 FROM desktop_renewals x JOIN connector_credentials c ON c.id=x.connector
 WHERE x.old_hash=? AND x.approved_until>? AND c.state='active' AND c.expires>?`, oldHash, now, now).
		Scan(&id, &owner, &state, &liveHash, &liveExpiry, &oldExpiry, &recordedHash, &newExpiry)
	if errors.Is(err, sql.ErrNoRows) {
		return RenewalReceipt{}, ErrRenewalUnavailable
	}
	if err != nil {
		return RenewalReceipt{}, err
	}
	if state == "completed" {
		if !sameSecret(newHash, recordedHash) || !sameSecret(liveHash, recordedHash) || liveExpiry != newExpiry {
			return RenewalReceipt{}, ErrRenewalConflict
		}
		return RenewalReceipt{ID: id, Expires: newExpiry}, tx.Commit()
	}
	if state != "approved" || !sameSecret(liveHash, oldHash) || liveExpiry != oldExpiry {
		return RenewalReceipt{}, ErrRenewalUnavailable
	}
	var used int
	if err = tx.QueryRowContext(ctx, `SELECT (EXISTS(SELECT 1 FROM desktop_renewals WHERE old_hash=?)) OR (EXISTS(SELECT 1 FROM connector_credentials WHERE token_hash=?))`, newHash, newHash).Scan(&used); err != nil {
		return RenewalReceipt{}, err
	}
	if used != 0 {
		return RenewalReceipt{}, ErrRenewalConflict
	}
	newExpiry = now + 3600
	if _, err = tx.ExecContext(ctx, `UPDATE desktop_renewals SET state='applied',new_hash=?,new_expires=? WHERE old_hash=?`, newHash, newExpiry, oldHash); err != nil {
		return RenewalReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE connector_credentials SET token_hash=?,expires=? WHERE id=?`, newHash, newExpiry, id); err != nil {
		return RenewalReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE desktop_renewals SET state='completed' WHERE old_hash=?`, oldHash); err != nil {
		return RenewalReceipt{}, err
	}
	if err = store.AuditTx(tx, owner, "desktop.credential_rotated", id, "completed", map[string]int64{"expires_unix": newExpiry}); err != nil {
		return RenewalReceipt{}, err
	}
	return RenewalReceipt{ID: id, Expires: newExpiry}, tx.Commit()
}
