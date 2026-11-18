// SPDX-License-Identifier: BUSL-1.1
package connector

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis.local/controller/internal/store"
)

func TestRenewalPinsCurrentTokenScopeAndOwnerApproval(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "renew.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	now := time.Now().UTC()
	old := PairedPrefix + strings.Repeat("a", 64)
	next := PairedPrefix + strings.Repeat("b", 64)
	candidate := PairedPrefix + strings.Repeat("c", 64)
	if _, err = s.DB.Exec("INSERT INTO owners VALUES('owner','fixture','now')"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO connector_credentials(id,owner,name,token_hash,scope,state,created_at,expires)
 VALUES('device','owner','Work device',?,'read_defence_v1','active','now',?)`, pairedCredentialHash(old), now.Add(20*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("INSERT INTO desktop_paired_connectors VALUES('device',0,'0123456789abcdef0123')"); err != nil {
		t.Fatal(err)
	}
	r := Registry{S: s, Now: func() time.Time { return now }}
	ctx := context.Background()
	if _, err = r.Renew(ctx, "Bearer "+old, pairedCredentialHash(next)); err != ErrRenewalUnavailable {
		t.Fatal("rotation allowed without owner approval")
	}
	if _, err = r.ApproveRenewal(ctx, "other", "device"); err != ErrRenewalUnavailable {
		t.Fatal("other owner approved rotation")
	}
	approval, err := r.ApproveRenewal(ctx, "owner", "device")
	if err != nil || approval.Until != now.Unix()+300 {
		t.Fatalf("unexpected approval: %v", err)
	}
	if _, err = s.DB.Exec("UPDATE connector_credentials SET token_hash='unexpected' WHERE id='device'"); err == nil {
		t.Fatal("database guard allowed unbound token update")
	}
	receipt, err := r.Renew(ctx, "Bearer "+old, pairedCredentialHash(next))
	if err != nil || receipt.ID != "device" || receipt.Expires != now.Unix()+3600 {
		t.Fatalf("rotation: %v", err)
	}
	if duplicate, e := r.Renew(ctx, "Bearer "+old, pairedCredentialHash(next)); e != nil || duplicate != receipt {
		t.Fatal("matching receipt was lost", e)
	}
	if _, err = r.Renew(ctx, "Bearer "+old, pairedCredentialHash(candidate)); err != ErrRenewalConflict {
		t.Fatal("old credential rotated to a different token")
	}
	if _, _, err = r.Authenticate("Bearer " + old); err != ErrInvalid {
		t.Fatal("old token remained valid")
	}
	owner, id, err := r.Authenticate("Bearer " + next)
	if err != nil || owner != "owner" || id != "device" || r.PairedRoute(ctx, id, "POST", "/desktop/drafts") {
		t.Fatal("rotation changed device identity or scope")
	}
	if _, err = r.ApproveRenewal(ctx, owner, id); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Renew(ctx, "Bearer "+next, pairedCredentialHash(old)); err != ErrRenewalConflict {
		t.Fatal("retired token could be restored")
	}
	now = now.Add(6 * time.Minute)
	if _, err = r.Renew(ctx, "Bearer "+old, pairedCredentialHash(next)); err != ErrRenewalUnavailable {
		t.Fatal("old receipt outlived approval window")
	}
	if _, err = r.Renew(ctx, "Bearer "+next, pairedCredentialHash(candidate)); err != ErrRenewalUnavailable {
		t.Fatal("unused approval outlived window")
	}
	if err = r.Revoke(owner, id); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ApproveRenewal(ctx, owner, id); err != ErrRenewalUnavailable {
		t.Fatal("revoked credential could renew")
	}
	var auditEvents int
	if err = s.DB.QueryRow("SELECT count(*) FROM audit WHERE json_extract(document,'$.action')='desktop.credential_rotated'").Scan(&auditEvents); err != nil || auditEvents != 1 {
		t.Fatalf("rotation audit count: %d, %v", auditEvents, err)
	}
}
