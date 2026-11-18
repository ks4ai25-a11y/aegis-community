// SPDX-License-Identifier: BUSL-1.1
package connector

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
)

func TestPairedCredentialCannotUseLegacyHash(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "pair.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if _, err = s.DB.Exec("INSERT INTO owners VALUES('owner','fixture','now')"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	reg := Registry{S: s, Now: func() time.Time { return now }}
	invitation, code, err := reg.Invite(ctx, "owner", "Fixture device", 15, false)
	if err != nil {
		t.Fatal(err)
	}
	legacy := prefix + strings.Repeat("a", 64)
	proof := strings.Repeat("b", 64)
	// Even an intentionally chosen hash must never upgrade paired access to
	// legacy authorization.
	digest := domain.Hash([]byte(legacy))
	if err = reg.ClaimPairing(ctx, invitation.ID, code, proof, digest); err != nil {
		t.Fatal(err)
	}
	claimed, err := reg.Pairing(ctx, "owner", invitation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = reg.DecidePairing(ctx, "owner", invitation.ID, claimed.Fingerprint, true); err != nil {
		t.Fatal(err)
	}
	if _, err = reg.RedeemPairing(ctx, invitation.ID, proof); err != nil {
		t.Fatal(err)
	}
	if _, _, err = reg.Authenticate("Bearer " + legacy); err != ErrInvalid {
		t.Fatal("paired row authenticated as legacy")
	}
	if _, _, err = reg.Authenticate("Bearer " + PairedPrefix + strings.Repeat("a", 64)); err != ErrInvalid {
		t.Fatal("paired hash domain was bypassed")
	}
	now = now.Add(6 * time.Minute)
	if _, err = reg.RedeemPairing(ctx, invitation.ID, proof); err != ErrPairingUnavailable {
		t.Fatal("expired invitation was redeemable")
	}
}
