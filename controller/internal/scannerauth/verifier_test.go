// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package scannerauth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func verifierFixture(t *testing.T) (*Registry, string, string, string) {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("positive operator UID required")
	}
	s, e := store.Open(filepath.Join(t.TempDir(), "verifier.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if _, e = s.DB.Exec("INSERT INTO owners VALUES('owner-a','test',?),('owner-b','test',?)", domain.Now(), domain.Now()); e != nil {
		t.Fatal(e)
	}
	s.Set("repository_mount_owner", "owner-a")
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(parent, 0700)
	os.Mkdir(filepath.Join(parent, "fixture"), 0700)
	os.WriteFile(filepath.Join(parent, "fixture", "app.py"), []byte("static only"), 0600)
	repos, e := repository.Open(s, parent)
	if e != nil {
		t.Fatal(e)
	}
	defer repos.Root.Close()
	if _, e = repos.Connect("owner-a", "app_demo", "fixture", true); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	r := &Registry{S: s, Now: func() time.Time { return now }}
	return r, parent, domain.Hash([]byte("engine")), domain.Hash([]byte("registry"))
}
func TestVerifierEnrollmentIsPrivateScopedDistinctAndRevocable(t *testing.T) {
	r, parent, engine, registry := verifierFixture(t)
	path := filepath.Join(parent, "verifier.token")
	v, e := r.EnrollVerifierFile("owner-a", "verifier-a", 1, engine, registry, path)
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
	got, e := r.AuthenticateVerifier(token)
	if e != nil || got != v {
		t.Fatal(got, e)
	}
	if v.Role != scanevidence.CleanupObserverRole || v.Engine != engine || v.Registry != registry {
		t.Fatal(v)
	}
	if _, e = r.Authenticate(token); !errors.Is(e, ErrDenied) {
		t.Fatal("verifier became worker", e)
	}
	worker, e := r.Enroll("owner-a", "worker-a", 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.AuthenticateVerifier(worker.Token); !errors.Is(e, ErrDenied) {
		t.Fatal("worker became verifier", e)
	}
	tx, e := r.S.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if e = AuthorizeVerifierTx(tx, v, r.now().Unix()); e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	if e = r.RevokeVerifier("owner-b", v.ID); !errors.Is(e, ErrDenied) {
		t.Fatal("cross owner revoke", e)
	}
	if e = r.RevokeVerifier("owner-a", v.ID); e != nil {
		t.Fatal(e)
	}
	if e = r.RevokeVerifier("owner-a", v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = r.AuthenticateVerifier(token); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked credential", e)
	}
	tx, _ = r.S.DB.Begin()
	if e = AuthorizeVerifierTx(tx, v, r.now().Unix()); !errors.Is(e, ErrDenied) {
		t.Fatal("stale authenticated identity survived revoke", e)
	}
	tx.Rollback()
	var audit string
	r.S.DB.QueryRow("SELECT group_concat(document) FROM audit").Scan(&audit)
	if strings.Contains(audit, token) || strings.Contains(audit, worker.Token) {
		t.Fatal("credential in audit")
	}
	for _, sql := range []string{"UPDATE scanner_verifiers SET state='active'", "UPDATE scanner_verifiers SET registry_digest='changed'", "UPDATE scanner_verifiers SET token_hash='changed'", "DELETE FROM scanner_verifiers"} {
		if _, e = r.S.DB.Exec(sql); e == nil {
			t.Fatal("retained enrollment altered")
		}
	}
	if e = r.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestVerifierEnrollmentRefusesUnsafePathsAndRollsBackFailedDelivery(t *testing.T) {
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
				path = "relative-verifier-test.token"
			case "unknown_owner":
				owner = "owner-b"
			case "invalid_scope":
				engine = "unix:///not-a-digest"
			case "invalid_lifetime":
				minutes = 1441
			case "audit_failure":
				_, e := r.S.DB.Exec("CREATE TRIGGER fail_verifier_audit BEFORE INSERT ON audit WHEN NEW.document LIKE '%scanner.verifier_enroll%' BEGIN SELECT RAISE(ABORT,'test failure'); END")
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e := r.EnrollVerifierFile(owner, "verifier-a", minutes, engine, registry, path); e == nil {
				t.Fatal("unsafe enrollment succeeded")
			}
			var n int
			r.S.DB.QueryRow("SELECT count(*) FROM scanner_verifiers").Scan(&n)
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
func TestVerifierExpiryBudgetsAndRevocationDoNotReleaseDispatch(t *testing.T) {
	r, parent, engine, registry := verifierFixture(t)
	base := r.now()
	r.Now = func() time.Time { return base }
	for i := 0; i < 4; i++ {
		if _, e := r.EnrollVerifierFile("owner-a", fmt.Sprintf("verifier-%d", i), 1, engine, registry, filepath.Join(parent, fmt.Sprintf("v%d", i))); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := r.EnrollVerifierFile("owner-a", "verifier-fifth", 1, engine, registry, filepath.Join(parent, "fifth")); !errors.Is(e, ErrConflict) {
		t.Fatal("active budget", e)
	}
	b, _ := os.ReadFile(filepath.Join(parent, "v0"))
	token := strings.TrimSpace(string(b))
	v, e := r.AuthenticateVerifier(token)
	if e != nil {
		t.Fatal(e)
	}
	base = base.Add(61 * time.Second)
	if _, e = r.AuthenticateVerifier(token); !errors.Is(e, ErrDenied) {
		t.Fatal("expired verifier", e)
	}
	tx, _ := r.S.DB.Begin()
	if e = AuthorizeVerifierTx(tx, v, r.now().Unix()); !errors.Is(e, ErrDenied) {
		t.Fatal("expired cached identity", e)
	}
	tx.Rollback()
	// Retained inactive enrollment budget is separate from the active limit.
	for i := 4; i < 100; i++ {
		base = base.Add(61 * time.Second)
		if _, e = r.EnrollVerifierFile("owner-a", fmt.Sprintf("verifier-%d", i), 1, engine, registry, filepath.Join(parent, fmt.Sprintf("v%d", i))); e != nil {
			t.Fatal(i, e)
		}
	}
	base = base.Add(61 * time.Second)
	if _, e = r.EnrollVerifierFile("owner-a", "verifier-over-total", 1, engine, registry, filepath.Join(parent, "over")); !errors.Is(e, ErrConflict) {
		t.Fatal("retained budget", e)
	}
	if _, e = r.EnrollVerifierFile("owner-a", "verifier-0", 1, engine, registry, filepath.Join(parent, "replacement")); !errors.Is(e, ErrConflict) {
		t.Fatal("retained ID reused", e)
	}
	if e = r.RevokeVerifier("owner-a", "verifier-0"); e != nil {
		t.Fatal(e)
	}
	var n int
	r.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n)
	if n != 0 {
		t.Fatal("revocation created dispatch")
	}
}
