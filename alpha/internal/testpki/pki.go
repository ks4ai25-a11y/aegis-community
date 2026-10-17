// SPDX-License-Identifier: BUSL-1.1
// Package testpki creates ephemeral keys only for isolated unit tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type Fixture struct {
	Directory string
	Server    tls.Certificate
	CA        []byte
	Client    []byte
	Key       []byte
	issue     func(string, time.Time, time.Time) ([]byte, []byte)
}

func New(t *testing.T, directory, role string) Fixture {
	t.Helper()
	if e := os.Mkdir(directory, 0700); e != nil {
		t.Fatal(e)
	}
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	caKey := key()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "unit-test-engine-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	makeCert := func(name string, server bool, notBefore, notAfter time.Time) ([]byte, []byte) {
		k := key()
		c := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.DNSNames = []string{"aegis-scanner-engine"}
		}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		private, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	client, private := makeCert(role, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	serverCert, serverKey := makeCert("aegis-scanner-engine", true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	server, e := tls.X509KeyPair(serverCert, serverKey)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	for name, b := range map[string][]byte{"ca.pem": caPEM, "client.pem": client, "client.key": private} {
		if e = os.WriteFile(filepath.Join(directory, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return Fixture{Directory: directory, Server: server, CA: caPEM, Client: client, Key: private, issue: func(role string, before, after time.Time) ([]byte, []byte) {
		return makeCert(role, false, before, after)
	}}
}

// AdditionalClientAt creates a separate private identity under the same test CA.
// The original client's key is never copied to the new identity directory.
func (f Fixture) AdditionalClientAt(t *testing.T, directory, role string, before, after time.Time) Fixture {
	t.Helper()
	if f.issue == nil {
		t.Fatal("test certificate issuer unavailable")
	}
	if e := os.Mkdir(directory, 0700); e != nil {
		t.Fatal(e)
	}
	client, key := f.issue(role, before, after)
	for name, b := range map[string][]byte{"ca.pem": f.CA, "client.pem": client, "client.key": key} {
		if e := os.WriteFile(filepath.Join(directory, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return Fixture{Directory: directory, Server: f.Server, CA: f.CA, Client: client, Key: key, issue: f.issue}
}
