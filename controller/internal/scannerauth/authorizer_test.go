// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package scannerauth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source/scanevidence"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthorizerEnrollmentIsPrivateScopedDistinctAndRevocable(t *testing.T) {
	r, parent, engine, registry := verifierFixture(t)
	path := filepath.Join(parent, "authorizer.token")
	v, e := r.EnrollAuthorizerFile("owner-a", "authorizer-a", 1, engine, registry, domain.Hash([]byte("policy")), path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) != 65 {
		t.Fatal("credential delivery", e)
	}
	token := strings.TrimSpace(string(b))
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("credential permissions")
	}
	got, e := r.AuthenticateAuthorizer(token)
	if e != nil || got != v {
		t.Fatal(got, e)
	}
	if v.Role != scanevidence.ScannerAuthorizerRole || v.Engine != engine || v.Registry != registry {
		t.Fatal(v)
	}
	if _, e = r.Authenticate(token); !errors.Is(e, ErrDenied) {
		t.Fatal("authorizer became worker", e)
	}
	if _, e = r.AuthenticateVerifier(token); !errors.Is(e, ErrDenied) {
		t.Fatal("authorizer became observer", e)
	}
	observerPath := filepath.Join(parent, "observer.token")
	if _, e = r.EnrollVerifierFile("owner-a", "observer-a", 1, engine, registry, observerPath); e != nil {
		t.Fatal(e)
	}
	observerBytes, e := os.ReadFile(observerPath)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.AuthenticateAuthorizer(strings.TrimSpace(string(observerBytes))); !errors.Is(e, ErrDenied) {
		t.Fatal("observer became authorizer", e)
	}
	for _, kind := range []string{"policy", "engine", "registry", "owner", "role"} {
		altered := v
		switch kind {
		case "policy":
			altered.Policy = domain.Hash([]byte("other"))
		case "engine":
			altered.Engine = domain.Hash([]byte("other"))
		case "registry":
			altered.Registry = domain.Hash([]byte("other"))
		case "owner":
			altered.Owner = "owner-b"
		case "role":
			altered.Role = scanevidence.CleanupObserverRole
		}
		tx, e := r.S.DB.Begin()
		if e != nil {
			t.Fatal(e)
		}
		e = AuthorizeAuthorizerTx(tx, altered, r.now().Unix())
		tx.Rollback()
		if !errors.Is(e, ErrDenied) {
			t.Fatal("altered cached scope accepted", kind, e)
		}
	}
	worker, e := r.Enroll("owner-a", "worker-a", 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.AuthenticateAuthorizer(worker.Token); !errors.Is(e, ErrDenied) {
		t.Fatal("worker became authorizer", e)
	}
	tx, e := r.S.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if e = AuthorizeAuthorizerTx(tx, v, r.now().Unix()); e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	if e = r.RevokeAuthorizer("owner-b", v.ID); !errors.Is(e, ErrDenied) {
		t.Fatal("cross owner revoke", e)
	}
	if e = r.RevokeAuthorizer("owner-a", v.ID); e != nil {
		t.Fatal(e)
	}
	if e = r.RevokeAuthorizer("owner-a", v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = r.AuthenticateAuthorizer(token); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked credential", e)
	}
	tx, _ = r.S.DB.Begin()
	if e = AuthorizeAuthorizerTx(tx, v, r.now().Unix()); !errors.Is(e, ErrDenied) {
		t.Fatal("stale authenticated identity survived revoke", e)
	}
	tx.Rollback()
	var audit string
	r.S.DB.QueryRow("SELECT group_concat(document) FROM audit").Scan(&audit)
	if strings.Contains(audit, token) || strings.Contains(audit, worker.Token) {
		t.Fatal("credential in audit")
	}
	for _, sql := range []string{"UPDATE scanner_authorizers SET state='active'", "UPDATE scanner_authorizers SET registry_digest='changed'", "UPDATE scanner_authorizers SET policy_digest='changed'", "UPDATE scanner_authorizers SET token_hash='changed'", "DELETE FROM scanner_authorizers"} {
		if _, e = r.S.DB.Exec(sql); e == nil {
			t.Fatal("retained enrollment altered")
		}
	}
	if e = r.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestAuthorizerEnrollmentRefusesUnsafePathsAndRollsBackFailedDelivery(t *testing.T) {
	for _, kind := range []string{"existing", "symlink", "parent_symlink", "public_parent", "relative", "unknown_owner", "invalid_scope", "invalid_lifetime", "audit_failure"} {
		t.Run(kind, func(t *testing.T) {
			r, parent, engine, registry := verifierFixture(t)
			path := filepath.Join(parent, "new.token")
			owner := "owner-a"
			minutes := 1
			switch kind {
			case "existing":
				os.WriteFile(path, []byte("existing marker"), 0600)
			case "symlink":
				os.WriteFile(filepath.Join(parent, "target"), []byte("existing marker"), 0600)
				os.Symlink("target", path)
			case "parent_symlink":
				link := filepath.Join(parent, "linked")
				os.Symlink(parent, link)
				path = filepath.Join(link, "new.token")
			case "public_parent":
				os.Chmod(parent, 0755)
			case "relative":
				path = "relative-authorizer-test.token"
			case "unknown_owner":
				owner = "owner-b"
			case "invalid_scope":
				engine = "unix:///not-a-digest"
			case "invalid_lifetime":
				minutes = 1441
			case "audit_failure":
				_, e := r.S.DB.Exec("CREATE TRIGGER fail_authorizer_audit BEFORE INSERT ON audit WHEN NEW.document LIKE '%scanner.authorizer_enroll%' BEGIN SELECT RAISE(ABORT,'test failure'); END")
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e := r.EnrollAuthorizerFile(owner, "authorizer-a", minutes, engine, registry, domain.Hash([]byte("policy")), path); e == nil {
				t.Fatal("unsafe enrollment succeeded")
			}
			var n int
			r.S.DB.QueryRow("SELECT count(*) FROM scanner_authorizers").Scan(&n)
			if n != 0 {
				t.Fatal("failed enrollment committed")
			}
			if kind == "existing" {
				b, _ := os.ReadFile(path)
				if string(b) != "existing marker" {
					t.Fatal("existing file overwritten")
				}
			}
			if kind == "unknown_owner" || kind == "invalid_scope" || kind == "invalid_lifetime" || kind == "audit_failure" {
				if _, e := os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("failed delivery retained a file")
				}
			}
		})
	}
}
func TestAuthorizerExpiryBudgetsAndRevocationDoNotReleaseDispatch(t *testing.T) {
	r, parent, engine, registry := verifierFixture(t)
	base := r.now()
	r.Now = func() time.Time { return base }
	for i := 0; i < 1; i++ {
		if _, e := r.EnrollAuthorizerFile("owner-a", fmt.Sprintf("authorizer-%d", i), 1, engine, registry, domain.Hash([]byte("policy")), filepath.Join(parent, fmt.Sprintf("v%d", i))); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := r.EnrollAuthorizerFile("owner-a", "authorizer-fifth", 1, engine, registry, domain.Hash([]byte("policy")), filepath.Join(parent, "fifth")); !errors.Is(e, ErrConflict) {
		t.Fatal("active budget", e)
	}
	b, _ := os.ReadFile(filepath.Join(parent, "v0"))
	token := strings.TrimSpace(string(b))
	v, e := r.AuthenticateAuthorizer(token)
	if e != nil {
		t.Fatal(e)
	}
	base = base.Add(61 * time.Second)
	if _, e = r.AuthenticateAuthorizer(token); !errors.Is(e, ErrDenied) {
		t.Fatal("expired authorizer", e)
	}
	tx, _ := r.S.DB.Begin()
	if e = AuthorizeAuthorizerTx(tx, v, r.now().Unix()); !errors.Is(e, ErrDenied) {
		t.Fatal("expired cached identity", e)
	}
	tx.Rollback()
	// Retained inactive enrollment budget is separate from the active limit.
	for i := 1; i < 100; i++ {
		base = base.Add(61 * time.Second)
		if _, e = r.EnrollAuthorizerFile("owner-a", fmt.Sprintf("authorizer-%d", i), 1, engine, registry, domain.Hash([]byte("policy")), filepath.Join(parent, fmt.Sprintf("v%d", i))); e != nil {
			t.Fatal(i, e)
		}
	}
	base = base.Add(61 * time.Second)
	if _, e = r.EnrollAuthorizerFile("owner-a", "authorizer-over-total", 1, engine, registry, domain.Hash([]byte("policy")), filepath.Join(parent, "over")); !errors.Is(e, ErrConflict) {
		t.Fatal("retained budget", e)
	}
	if _, e = r.EnrollAuthorizerFile("owner-a", "authorizer-0", 1, engine, registry, domain.Hash([]byte("policy")), filepath.Join(parent, "replacement")); !errors.Is(e, ErrConflict) {
		t.Fatal("retained ID reused", e)
	}
	if e = r.RevokeAuthorizer("owner-a", "authorizer-0"); e != nil {
		t.Fatal(e)
	}
	var n int
	r.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 0 {
		t.Fatal("revocation created dispatch")
	}
}
