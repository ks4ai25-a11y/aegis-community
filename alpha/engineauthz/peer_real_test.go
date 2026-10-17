// SPDX-License-Identifier: Apache-2.0
package engineauthz_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Called only inside the existing guarded Linux fixture. The disposable test
// issuer creates one in-memory short-lived client; no production issuer or
// broker private key is accessed and no mutation is sent or retried.
func verifyRealPeerExpiry(t *testing.T, endpoint, root string) {
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, "tls", name))
		if err != nil {
			t.Fatal("private test issuer unavailable")
		}
		return raw
	}
	caRaw := read("ca.pem")
	block, _ := pem.Decode(caRaw)
	if block == nil {
		t.Fatal("private test issuer unavailable")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("private test issuer unavailable")
	}
	keyBlock, _ := pem.Decode(read("ca.key"))
	if keyBlock == nil {
		t.Fatal("private test issuer unavailable")
	}
	issuer, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal("private test issuer unavailable")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("private test identity unavailable")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal("private test identity unavailable")
	}
	expires := time.Now().Add(4 * time.Second).Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "aegis-engine-broker"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, issuer)
	if err != nil {
		t.Fatal("private test identity unavailable")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caRaw)
	tr := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, ResponseHeaderTimeout: 2 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "aegis-scanner-engine", NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	check := func(want int, reuseRequired bool) {
		t.Helper()
		req, err := http.NewRequest("GET", endpoint+"/v1.55/info", nil)
		if err != nil {
			t.Fatal("private expiry request unavailable")
		}
		reused := false
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("native cached expiry check unavailable")
		}
		n, err := io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
		response.Body.Close()
		if err != nil || n > 65536 || response.StatusCode != want || reuseRequired && !reused {
			t.Fatal("native cached certificate expiry was not enforced")
		}
	}
	check(http.StatusOK, false)
	time.Sleep(time.Until(expires) + 20*time.Millisecond)
	check(http.StatusForbidden, true)
}
