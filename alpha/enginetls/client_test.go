// SPDX-License-Identifier: BUSL-1.1
package enginetls

import (
	"aegis.local/alpha/internal/testpki"
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) testpki.Fixture {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return testpki.New(t, filepath.Join(root, "client"), Broker)
}
func TestIdentityIsBoundToPublicCertificatesAndReread(t *testing.T) {
	f := fixture(t)
	i, e := Load(f.Directory, Broker)
	if e != nil {
		t.Fatal(e)
	}
	if i.TLS.MinVersion != tls.VersionTLS13 || i.TLS.ServerName != ServerName || len(i.TLS.NextProtos) != 1 || i.TLS.NextProtos[0] != "http/1.1" || i.Digest == "" || i.Check() != nil {
		t.Fatal("unsafe TLS configuration")
	}
	old := i.Digest
	if e = os.WriteFile(filepath.Join(f.Directory, "client.key"), []byte("withdrawn"), 0600); e != nil {
		t.Fatal(e)
	}
	if i.Check() == nil {
		t.Fatal("cached authority survived withdrawal")
	}
	os.WriteFile(filepath.Join(f.Directory, "client.key"), f.Key, 0600)
	j, e := Load(f.Directory, Broker)
	if e != nil || j.Digest != old {
		t.Fatal("same identity changed scope")
	}
	g := testpki.New(t, filepath.Join(filepath.Dir(f.Directory), "different"), Broker)
	for name, b := range map[string][]byte{"ca.pem": g.CA, "client.pem": g.Client, "client.key": g.Key} {
		os.WriteFile(filepath.Join(f.Directory, name), b, 0600)
	}
	if i.Check() == nil {
		t.Fatal("replacement acquired old identity authority")
	}
	if bytes.Contains([]byte(i.Digest), f.Key) {
		t.Fatal("key material in public identity")
	}
}
func TestPrivateIdentityFileRefusals(t *testing.T) {
	for _, kind := range []string{"public-directory", "symlink-directory", "public-key", "missing-key", "hardlink", "symlink", "oversize", "invalid-cert", "wrong-key", "extra-root", "observer-role", "unknown-role", "relative", "extra-file"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			dir := f.Directory
			switch kind {
			case "public-directory":
				os.Chmod(dir, 0755)
			case "symlink-directory":
				link := filepath.Join(filepath.Dir(dir), "link")
				os.Symlink(dir, link)
				dir = link
			case "public-key":
				os.Chmod(filepath.Join(dir, "client.key"), 0644)
			case "missing-key":
				os.Remove(filepath.Join(dir, "client.key"))
			case "hardlink":
				os.Link(filepath.Join(dir, "client.key"), filepath.Join(filepath.Dir(dir), "extra"))
			case "symlink":
				os.Remove(filepath.Join(dir, "client.key"))
				os.WriteFile(filepath.Join(filepath.Dir(dir), "target"), f.Key, 0600)
				os.Symlink(filepath.Join(filepath.Dir(dir), "target"), filepath.Join(dir, "client.key"))
			case "oversize":
				os.WriteFile(filepath.Join(dir, "client.key"), bytes.Repeat([]byte("x"), 16385), 0600)
			case "invalid-cert":
				os.WriteFile(filepath.Join(dir, "client.pem"), []byte("invalid"), 0600)
			case "wrong-key":
				g := testpki.New(t, filepath.Join(filepath.Dir(dir), "other"), Broker)
				os.WriteFile(filepath.Join(dir, "client.key"), g.Key, 0600)
			case "extra-root":
				os.WriteFile(filepath.Join(dir, "ca.pem"), append(f.CA, f.CA...), 0600)
			case "observer-role":
				os.RemoveAll(dir)
				testpki.New(t, dir, "aegis-engine-observer")
			case "unknown-role":
				if _, e := Load(dir, "unknown"); e == nil {
					t.Fatal("unknown role accepted")
				}
				return
			case "extra-file":
				os.WriteFile(filepath.Join(dir, "ca.key"), []byte("must-not-be-mounted"), 0600)
			case "relative":
				dir = "relative"
			}
			if _, e := Load(dir, Broker); e == nil {
				t.Fatal("unsafe identity accepted")
			}
		})
	}
}
