//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package recovery

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionSeventeenRestoreRevokesReconcilerButPreservesOriginalScope(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	if err := s.Set("repository_mount_owner", "owner"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	b := scanevidence.MutationBinding{Owner: "owner", Authorizer: "original-authorizer", Engine: domain.Hash([]byte("engine")), Registry: domain.Hash([]byte("registry")), Policy: domain.Hash([]byte("policy")), Namespace: domain.Hash([]byte("namespace")), Broker: domain.Hash([]byte("broker")), Created: now.Format(time.RFC3339Nano)}
	b.Digest = domain.Digest(b)
	if _, err := s.DB.Exec("INSERT INTO scanner_authorizers VALUES(?,?,?,'revoked',?,?,?,?,?)", b.Authorizer, b.Owner, domain.Hash([]byte("fixed synthetic old token hash")), b.Engine, b.Registry, b.Policy, now.Add(time.Hour).Unix(), b.Created); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO scanner_mutation_bindings VALUES(?,?,?,?,?,?,?,?,?,'revoked')", b.Digest, b.Owner, b.Authorizer, b.Engine, b.Registry, b.Policy, b.Namespace, b.Broker, b.Created); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(parent, "reconciler-private")
	if os.Mkdir(private, 0700) != nil {
		t.Fatal("private credential directory unavailable")
	}
	credential := filepath.Join(private, "reconciler.token")
	v, err := (&scannerauth.Registry{S: s}).EnrollReconcilerFile("owner", "reconciler-a", 60, b.Digest, credential)
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(credential)
	if err != nil {
		t.Fatal(err)
	}
	bundle, receipt := makeBundle(t, c, parent)
	destination := filepath.Join(parent, "restored17")
	if _, err = Restore(context.Background(), c, bundle, destination, receipt.Bundle); err != nil {
		t.Fatal(err)
	}
	restored, err := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	var state, binding, capability string
	if err = restored.DB.QueryRow("SELECT state,binding_digest,capability FROM scanner_reconcilers WHERE id=?", v.ID).Scan(&state, &binding, &capability); err != nil || state != "revoked" || binding != b.Digest || capability != scanevidence.ConfirmFencedCleanup {
		t.Fatal("restore changed or retained live reconciler authority", err)
	}
	if _, err = (&scannerauth.Registry{S: restored}).AuthenticateReconciler(strings.TrimSpace(string(token))); err == nil {
		t.Fatal("old reconciler credential survived restore")
	}
	if err = restored.DB.QueryRow("SELECT state FROM scanner_dispatch WHERE job='scan'").Scan(&state); err != nil || state != "cleanup_required" {
		t.Fatal("reconciler revocation released dispatch", err)
	}
	if restored.VerifyAuditContext(context.Background()) != nil {
		t.Fatal("restored audit invalid")
	}
}

func TestRecoveryRequiresReconcilerTableToMatchDeclaredVersion(t *testing.T) {
	for _, kind := range []string{"missing-table", "undeclared-table"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			statement := "DROP TABLE scanner_reconcilers"
			if kind == "undeclared-table" {
				statement = "DELETE FROM migrations WHERE version=17"
			}
			if _, err := s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := Create(context.Background(), c, filepath.Join(parent, "refused17")); err != ErrRecovery {
				t.Fatal("reconciler table/version mismatch accepted", err)
			}
		})
	}
}

func TestRecoveryRequiresCleanupConfirmationTableToMatchDeclaredVersion(t *testing.T) {
	for _, kind := range []string{"missing-table", "undeclared-table"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			statement := "DROP TRIGGER scanner_generation_release_confirmed; DROP TRIGGER scanner_cleanup_confirmation_scoped; DROP TABLE scanner_cleanup_confirmations"
			if kind == "undeclared-table" {
				statement = "DELETE FROM migrations WHERE version>=18"
			}
			if _, err := s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := Create(context.Background(), c, filepath.Join(parent, "refused18")); err != ErrRecovery {
				t.Fatal("cleanup confirmation table/version mismatch accepted", err)
			}
		})
	}
}

func TestRecoveryRequiresReleaseGuardsToMatchDeclaredVersion(t *testing.T) {
	for _, kind := range []string{"missing-trigger", "undeclared-trigger"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			statement := "DROP TRIGGER scanner_generation_release_confirmed"
			if kind == "undeclared-trigger" {
				statement = "DELETE FROM migrations WHERE version=19"
			}
			if _, err := s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := Create(context.Background(), c, filepath.Join(parent, "refused19")); err != ErrRecovery {
				t.Fatal("release guard/version mismatch accepted", err)
			}
		})
	}
}

func TestRecoveryRequiresRepairTableToMatchDeclaredVersion(t *testing.T) {
	for _, kind := range []string{"missing-table", "undeclared-table"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			statement := "DROP TABLE scanner_mutation_repairs"
			if kind == "undeclared-table" {
				statement = "DELETE FROM migrations WHERE version=20"
			}
			if _, err := s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := Create(context.Background(), c, filepath.Join(parent, "refused20")); err != ErrRecovery {
				t.Fatal("repair table/version mismatch accepted", err)
			}
		})
	}
}
