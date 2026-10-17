// SPDX-License-Identifier: Apache-2.0
package enginetls

import (
	"aegis.local/alpha/internal/testpki"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitObserverIdentityKeepsItsRoleOnEveryCheck(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := testpki.New(t, filepath.Join(root, "observer"), Observer)
	i, err := Load(f.Directory, Observer)
	if err != nil || i.Check() != nil {
		t.Fatal("explicit observer identity unavailable", err)
	}
	if _, err = Load(f.Directory, Broker); err == nil {
		t.Fatal("observer certificate acquired broker identity")
	}
	broker := fixture(t)
	if _, err = Load(broker.Directory, Observer); err == nil {
		t.Fatal("broker certificate acquired observer identity")
	}
	callback := i.TLS.GetClientCertificate
	if _, err = callback(&tls.CertificateRequestInfo{}); err != nil {
		t.Fatal("observer certificate refresh lost role", err)
	}
	if err = os.Remove(filepath.Join(f.Directory, "client.key")); err != nil {
		t.Fatal(err)
	}
	if i.Check() == nil {
		t.Fatal("observer reused withdrawn credential")
	}
	if _, err = callback(&tls.CertificateRequestInfo{}); err == nil {
		t.Fatal("TLS callback reused withdrawn observer credential")
	}
	if err = os.WriteFile(filepath.Join(f.Directory, "client.key"), f.Key, 0600); err != nil {
		t.Fatal(err)
	}
	if i.Check() != nil {
		t.Fatal("restored original credential changed identity")
	}
	replacement := testpki.New(t, filepath.Join(root, "replacement"), Observer)
	for name, data := range map[string][]byte{"ca.pem": replacement.CA, "client.pem": replacement.Client, "client.key": replacement.Key} {
		if err = os.WriteFile(filepath.Join(f.Directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if i.Check() == nil {
		t.Fatal("replacement observer acquired old identity")
	}
	if _, err = callback(&tls.CertificateRequestInfo{}); err == nil {
		t.Fatal("TLS callback accepted replacement observer")
	}
}

func TestUnloadedIdentityHasNoImplicitRole(t *testing.T) {
	f := fixture(t)
	i, err := Load(f.Directory, Broker)
	if err != nil {
		t.Fatal(err)
	}
	unloaded := &Identity{Directory: i.Directory, Digest: i.Digest, TLS: i.TLS}
	if unloaded.Check() == nil {
		t.Fatal("constructed identity silently selected broker role")
	}
}
