// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegis.local/controller/internal/desktopmtls"
)

func desktopTLSFixture(t *testing.T, handler http.Handler, dir string, owner *http.Cookie) (string, []string) {
	t.Helper()
	now := time.Now()
	issue := func(serial int64, label string, usage x509.ExtKeyUsage, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		spec := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: label},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature}
		if ca == nil {
			spec.IsCA = true
			spec.KeyUsage |= x509.KeyUsageCertSign
			ca, caKey = spec, key
		} else {
			spec.ExtKeyUsage = []x509.ExtKeyUsage{usage}
			if usage == x509.ExtKeyUsageServerAuth {
				spec.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, spec, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	serverCA, serverCAKey, serverCAPEM := issue(1, "server root", 0, nil, nil)
	clientCA, clientCAKey, clientCAPEM := issue(2, "client root", 0, nil, nil)
	_, serverKey, serverPEM := issue(3, "server", x509.ExtKeyUsageServerAuth, serverCA, serverCAKey)
	clientCert, clientKey, clientPEM := issue(4, "client", x509.ExtKeyUsageClientAuth, clientCA, clientCAKey)
	untrustedCert, untrustedKey, _ := issue(5, "untrusted client", x509.ExtKeyUsageClientAuth, serverCA, serverCAKey)
	roots := x509.NewCertPool()
	roots.AddCert(serverCA)
	writeFile := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	writeKey := func(name string, key *ecdsa.PrivateKey) string {
		t.Helper()
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return writeFile(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	config, err := desktopmtls.ServerConfig(writeFile("server.pem", serverPEM), writeKey("server-key.pem", serverKey), writeFile("client-ca.pem", clientCAPEM))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = config
	server.StartTLS()
	t.Cleanup(server.Close)

	authenticated := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{clientCert.Raw}, PrivateKey: clientKey}}}
	probe := func(method, path string, config *tls.Config, cookie *http.Cookie, want int) {
		t.Helper()
		tr := &http.Transport{TLSClientConfig: config}
		t.Cleanup(tr.CloseIdleConnections)
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		request, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			if want == 0 {
				return
			}
			t.Fatalf("desktop TLS probe failed: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("desktop TLS probe got %d, expected %d", response.StatusCode, want)
		}
	}
	noCert := authenticated.Clone()
	noCert.Certificates = nil
	probe(http.MethodGet, "/api/v1/desktop/status", noCert, nil, 0)
	wrongCert := authenticated.Clone()
	wrongCert.Certificates = []tls.Certificate{{Certificate: [][]byte{untrustedCert.Raw}, PrivateKey: untrustedKey}}
	probe(http.MethodGet, "/api/v1/desktop/status", wrongCert, nil, 0)
	wrongHost := authenticated.Clone()
	wrongHost.ServerName = "wrong.invalid"
	probe(http.MethodGet, "/api/v1/desktop/status", wrongHost, nil, 0)
	for _, path := range []string{"/", "/api/v1/health/live", "/api/v1/connectors", "/api/v1/desktop/pairing", "/api/v1/desktop/handoff-preview", "/api/v1/desktop/status"} {
		probe(http.MethodGet, path, authenticated, owner, http.StatusForbidden)
		probe(http.MethodGet, path, authenticated, nil, http.StatusForbidden)
	}
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/connectors", "/api/v1/desktop/handoffs", "/api/v1/desktop/handoff-preview"} {
		probe(http.MethodPost, path, authenticated, owner, http.StatusForbidden)
		probe(http.MethodPost, path, authenticated, nil, http.StatusForbidden)
	}
	return server.URL, []string{
		"AEGIS_DESKTOP_CA_FILE=" + writeFile("server-ca.pem", serverCAPEM),
		"AEGIS_DESKTOP_CLIENT_CERT_FILE=" + writeFile("client.pem", clientPEM),
		"AEGIS_DESKTOP_CLIENT_KEY_FILE=" + writeKey("client-key.pem", clientKey),
	}
}
