// SPDX-License-Identifier: Apache-2.0
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
	makeCert := func(name string, server bool) ([]byte, []byte) {
		k := key()
		c := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
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
	client, private := makeCert(role, false)
	serverCert, serverKey := makeCert("aegis-scanner-engine", true)
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
	return Fixture{directory, server, caPEM, client, private}
}
