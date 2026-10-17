//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerauth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reconcilerFixture(t *testing.T) (*Registry, string, string) {
	t.Helper()
	r, parent, engine, registry := verifierFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	r.Now = func() time.Time { return now }
	policy := domain.Hash([]byte("policy"))
	v, err := r.EnrollAuthorizerFile("owner-a", "authorizer-a", 60, engine, registry, policy, filepath.Join(parent, "authorizer.token"))
	if err != nil {
		t.Fatal(err)
	}
	b := scanevidence.MutationBinding{Owner: v.Owner, Authorizer: v.ID, Engine: engine, Registry: registry, Policy: policy, Namespace: domain.Hash([]byte("namespace")), Broker: domain.Hash([]byte("broker")), Created: now.Format(time.RFC3339Nano)}
	b.Digest = domain.Digest(b)
	if _, err = r.S.DB.Exec("INSERT INTO scanner_mutation_bindings VALUES(?,?,?,?,?,?,?,?,?,'active')", b.Digest, b.Owner, b.Authorizer, b.Engine, b.Registry, b.Policy, b.Namespace, b.Broker, b.Created); err != nil {
		t.Fatal(err)
	}
	return r, parent, b.Digest
}

func TestReconcilerIsPrivateScopedDistinctRetainedAndRevocable(t *testing.T) {
	r, parent, binding := reconcilerFixture(t)
	path := filepath.Join(parent, "reconciler.token")
	v, err := r.EnrollReconcilerFile("owner-a", "reconciler-a", 60, binding, path)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil || len(bytes) != 65 || bytes[64] != '\n' {
		t.Fatal("private reconciler credential unavailable")
	}
	token := strings.TrimSpace(string(bytes))
	got, err := r.AuthenticateReconciler(token)
	if err != nil || got != v || !v.Valid(r.now()) || v.Binding != binding || v.Role != scanevidence.ScannerReconcilerRole || v.Capability != scanevidence.ConfirmFencedCleanup {
		t.Fatal("scoped reconciler identity unavailable", err)
	}
	for _, auth := range []func(string) error{
		func(s string) error { _, e := r.Authenticate(s); return e },
		func(s string) error { _, e := r.AuthenticateVerifier(s); return e },
		func(s string) error { _, e := r.AuthenticateAuthorizer(s); return e },
	} {
		if !errors.Is(auth(token), ErrDenied) {
			t.Fatal("reconciler acquired another role")
		}
	}
	other, err := os.ReadFile(filepath.Join(parent, "authorizer.token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.AuthenticateReconciler(strings.TrimSpace(string(other))); !errors.Is(err, ErrDenied) {
		t.Fatal("authorizer acquired independent reconciliation role")
	}
	for _, kind := range []string{"owner", "id", "binding", "engine", "registry", "policy", "namespace", "role", "capability", "expires", "created"} {
		altered := v
		switch kind {
		case "owner":
			altered.Owner = "owner-b"
		case "id":
			altered.ID = "different-reconciler"
		case "binding":
			altered.Binding = domain.Hash([]byte("other"))
		case "engine":
			altered.Engine = domain.Hash([]byte("other"))
		case "registry":
			altered.Registry = domain.Hash([]byte("other"))
		case "policy":
			altered.Policy = domain.Hash([]byte("other"))
		case "namespace":
			altered.Namespace = domain.Hash([]byte("other"))
		case "role":
			altered.Role = scanevidence.CleanupObserverRole
		case "capability":
			altered.Capability = "reset"
		case "expires":
			altered.Expires = r.now().Add(2 * time.Hour).Format(time.RFC3339)
		case "created":
			altered.Created = r.now().Add(-time.Minute).Format(time.RFC3339Nano)
		}
		tx, err := r.S.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		err = AuthorizeReconcilerTx(tx, altered, r.now().Unix())
		tx.Rollback()
		if !errors.Is(err, ErrDenied) {
			t.Fatal("altered reconciler scope accepted", kind)
		}
	}
	if r.RevokeReconciler("owner-b", v.ID) != ErrDenied {
		t.Fatal("other owner revoked role")
	}
	if err = r.RevokeReconciler(v.Owner, v.ID); err != nil {
		t.Fatal(err)
	}
	if err = r.RevokeReconciler(v.Owner, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = r.AuthenticateReconciler(token); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked role authenticated")
	}
	for _, statement := range []string{"UPDATE scanner_reconcilers SET state='active'", "UPDATE scanner_reconcilers SET binding_digest='changed'", "UPDATE scanner_reconcilers SET token_hash='changed'", "UPDATE scanner_reconcilers SET capability='other'", "UPDATE scanner_reconcilers SET expires=2147483647", "DELETE FROM scanner_reconcilers"} {
		if _, err = r.S.DB.Exec(statement); err == nil {
			t.Fatal("retained reconciler scope altered")
		}
	}
	var audit string
	if err = r.S.DB.QueryRow("SELECT group_concat(document) FROM audit").Scan(&audit); err != nil || strings.Contains(audit, token) || r.S.VerifyAudit() != nil {
		t.Fatal("credential leaked or audit invalid", err)
	}
}

func TestReconcilerEnrollmentRefusalsAndFailedDeliveryLeaveNoAuthority(t *testing.T) {
	for _, kind := range []string{"existing", "symlink", "parent-symlink", "public-parent", "relative", "wrong-binding", "mismatched-authorizer", "wrong-owner", "lifetime", "audit-failure", "delivery-failure"} {
		t.Run(kind, func(t *testing.T) {
			r, parent, binding := reconcilerFixture(t)
			path, owner, minutes := filepath.Join(parent, "new.token"), "owner-a", 60
			switch kind {
			case "existing":
				os.WriteFile(path, []byte("unchanged"), 0600)
			case "symlink":
				os.Symlink("missing", path)
			case "parent-symlink":
				link := filepath.Join(parent, "link")
				os.Symlink(parent, link)
				path = filepath.Join(link, "new.token")
			case "public-parent":
				os.Chmod(parent, 0755)
			case "relative":
				path = "relative-token"
			case "wrong-binding":
				binding = domain.Hash([]byte("unknown"))
			case "mismatched-authorizer":
				original, err := reconcilerBinding(r.S.DB, owner, binding)
				if err != nil {
					t.Fatal(err)
				}
				d := original.Document
				d.Engine = domain.Hash([]byte("different engine"))
				binding = domain.Digest(d)
				if _, err = r.S.DB.Exec("INSERT INTO scanner_mutation_bindings VALUES(?,?,?,?,?,?,?,?,?,'revoked')", binding, d.Owner, d.Authorizer, d.Engine, d.Registry, d.Policy, d.Namespace, d.Broker, d.Created); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner = "owner-b"
			case "lifetime":
				minutes = 1441
			case "audit-failure":
				if _, err := r.S.DB.Exec(`CREATE TRIGGER refuse_reconciler BEFORE INSERT ON audit WHEN json_extract(NEW.document,'$.action')='scanner.reconciler_enroll' BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if kind == "delivery-failure" {
				_, err = r.enrollReconciler(owner, "reconciler-a", minutes, binding, func(string) error { return ErrCredential })
			} else {
				_, err = r.EnrollReconcilerFile(owner, "reconciler-a", minutes, binding, path)
			}
			if err == nil {
				t.Fatal("unsafe enrollment succeeded")
			}
			var count int
			if err = r.S.DB.QueryRow("SELECT count(*) FROM scanner_reconcilers").Scan(&count); err != nil || count != 0 {
				t.Fatal("failed enrollment retained capability", err)
			}
			if kind == "existing" {
				b, _ := os.ReadFile(path)
				if string(b) != "unchanged" {
					t.Fatal("existing file overwritten")
				}
			}
		})
	}
}

func TestReconcilerExpiredAndRevokedBindingsRemainInspectableButNotRenewable(t *testing.T) {
	r, parent, binding := reconcilerFixture(t)
	if _, err := r.S.DB.Exec("UPDATE scanner_mutation_bindings SET state='revoked' WHERE digest=?", binding); err != nil {
		t.Fatal(err)
	}
	v, err := r.EnrollReconcilerFile("owner-a", "reconciler-a", 1, binding, filepath.Join(parent, "first.token"))
	if err != nil {
		t.Fatal("retained binding could not be diagnosed", err)
	}
	if _, err = r.EnrollReconcilerFile("owner-a", "reconciler-b", 1, binding, filepath.Join(parent, "second.token")); err != ErrConflict {
		t.Fatal("duplicate active scope allowed", err)
	}
	now := r.now().Add(time.Minute)
	r.Now = func() time.Time { return now }
	tx, err := r.S.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = AuthorizeReconcilerTx(tx, v, now.Unix())
	tx.Rollback()
	if !errors.Is(err, ErrDenied) {
		t.Fatal("expired cached identity accepted")
	}
	if _, err = r.EnrollReconcilerFile("owner-a", "reconciler-a", 1, binding, filepath.Join(parent, "reused.token")); err != ErrConflict {
		t.Fatal("expired identity was overwritten", err)
	}
	if _, err = r.EnrollReconcilerFile("owner-a", "reconciler-b", 1, binding, filepath.Join(parent, "new.token")); err != nil {
		t.Fatal(err)
	}
}
