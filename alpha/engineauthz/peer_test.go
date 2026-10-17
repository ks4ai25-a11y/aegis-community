// SPDX-License-Identifier: Apache-2.0
package engineauthz

import (
	"aegis.local/alpha/internal/testpki"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiredNativePeerCannotReuseAuthorization(t *testing.T) {
	p, _, create := fixture(t)
	now := time.Now()
	f := testpki.New(t, filepath.Join(t.TempDir(), "original"), Broker)
	expired := f.AdditionalClientAt(t, filepath.Join(t.TempDir(), "expired"), Broker, now.Add(-2*time.Hour), now.Add(-time.Hour))
	read := call("GET", "/info")
	read.RequestPeerCertificates = [][]byte{expired.Client}
	if p.AuthorizeRequest(read).Allow || p.AuthorizeResponse(read).Allow {
		t.Fatal("expired authenticated peer retained read authority")
	}
	create.RequestPeerCertificates = [][]byte{expired.Client}
	if p.AuthorizeRequest(create).Allow {
		t.Fatal("expired authenticated peer admitted a native mutation")
	}
	if o := p.Observation(); o.Unresolved != 0 || o.Attempts != 0 {
		t.Fatal("denied peer created journal obligations")
	}
}

func TestNativePeerEnvelopeRefusals(t *testing.T) {
	p, _, _ := fixture(t)
	now := time.Now()
	f := testpki.New(t, filepath.Join(t.TempDir(), "original"), Broker)
	future := f.AdditionalClientAt(t, filepath.Join(t.TempDir(), "future"), Broker, now.Add(time.Hour), now.Add(2*time.Hour))
	cases := map[string][][]byte{
		"missing": nil, "empty": {}, "null-leaf": {nil}, "malformed": {[]byte("not a certificate")},
		"der-instead-of-pem": {f.Server.Certificate[0]}, "wrong-principal": nativeTestPeer(Observer),
		"not-yet-valid": {future.Client}, "server-only": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate[0]})},
		"ca-leaf": {f.CA}, "extra-pem": {append(append([]byte(nil), f.Client...), f.Client...)},
		"trailing-data": {append(append([]byte(nil), f.Client...), []byte("private trailer")...)},
		"prefixed-data": {append([]byte("private prefix"), f.Client...)}, "oversized": {bytes.Repeat([]byte("x"), 16385)},
		"too-many": {f.Client, f.Client, f.Client, f.Client, f.Client, f.Client, f.Client, f.Client, f.Client},
	}
	for name, chain := range cases {
		t.Run(name, func(t *testing.T) {
			r := call("GET", "/info")
			r.RequestPeerCertificates = chain
			if p.AuthorizeRequest(r).Allow || p.AuthorizeResponse(r).Allow {
				t.Fatal("invalid native peer accepted")
			}
		})
	}
	r := call("GET", "/info")
	r.RequestPeerCertificates = [][]byte{f.Client, f.CA}
	must(t, p.AuthorizeRequest(r), true)
	block, _ := pem.Decode(f.Client)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !nativePeer(r, cert.NotBefore) || nativePeer(r, cert.NotAfter) || nativePeer(r, cert.NotBefore.Add(-time.Nanosecond)) {
		t.Fatal("certificate validity boundaries incorrect")
	}
}

func TestNativeResponseCannotChangeAuthenticatedCertificate(t *testing.T) {
	p, _, r := fixture(t)
	must(t, p.AuthorizeRequest(r), true)
	r.ResponseStatusCode = 201
	r.ResponseBody = []byte(`{"Id":"` + testID + `","Warnings":[]}`)
	original := r.RequestPeerCertificates
	f := testpki.New(t, filepath.Join(t.TempDir(), "replacement"), Broker)
	r.RequestPeerCertificates = [][]byte{f.Client}
	must(t, p.AuthorizeResponse(r), false)
	if p.Observation().Unresolved != 1 {
		t.Fatal("changed peer settled pending mutation")
	}
	r.RequestPeerCertificates = original
	must(t, p.AuthorizeResponse(r), true)
}

// A miniature authenticated daemon reproduces the TLS keepalive boundary. It
// does not start Docker, open an engine socket or authorize an engine mutation.
func TestNativePeerExpiresOnReusedTLSConnection(t *testing.T) {
	p, _, _ := fixture(t)
	f := testpki.New(t, filepath.Join(t.TempDir(), "original"), Broker)
	short := f.AdditionalClientAt(t, filepath.Join(t.TempDir(), "short"), Broker, time.Now().Add(-time.Minute), time.Now().Add(4*time.Second))
	block, _ := pem.Decode(short.Client)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(short.Client, short.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(f.CA)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelope := Request{User: Broker, UserAuthNMethod: "TLS", RequestMethod: "GET", RequestURI: api + "/info"}
		for _, cert := range r.TLS.PeerCertificates {
			envelope.RequestPeerCertificates = append(envelope.RequestPeerCertificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
		if !p.AuthorizeRequest(envelope).Allow || !p.AuthorizeResponse(envelope).Allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.Server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "aegis-scanner-engine", Certificates: []tls.Certificate{pair}}, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	get := func(want int, requireReused bool) {
		t.Helper()
		req, _ := http.NewRequest("GET", server.URL, nil)
		reused := false
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("isolated TLS request failed")
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != want || requireReused && !reused {
			t.Fatal("cached TLS authority was not rechecked")
		}
	}
	get(http.StatusOK, false)
	time.Sleep(time.Until(leaf.NotAfter) + 20*time.Millisecond)
	get(http.StatusForbidden, true)
	if p.Observation().Attempts != 0 {
		t.Fatal("read-only expiry test created an allocation")
	}
}

func TestNativeCallbackExpiryPreservesUnresolvedMutation(t *testing.T) {
	p, cfg, r := fixture(t)
	f := testpki.New(t, filepath.Join(t.TempDir(), "original"), Broker)
	short := f.AdditionalClientAt(t, filepath.Join(t.TempDir(), "short"), Broker, time.Now().Add(-time.Minute), time.Now().Add(3*time.Second))
	block, _ := pem.Decode(short.Client)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	r.RequestPeerCertificates = [][]byte{short.Client}
	must(t, p.AuthorizeRequest(r), true)
	time.Sleep(time.Until(leaf.NotAfter) + 20*time.Millisecond)
	r.ResponseStatusCode = 201
	r.ResponseBody = []byte(`{"Id":"` + testID + `","Warnings":[]}`)
	must(t, p.AuthorizeResponse(r), false)
	if o := p.Observation(); o.Unresolved != 1 || o.Unfinished != 1 {
		t.Fatal("expired callback discharged uncertain engine state")
	}
	p.Close()
	if reopened, err := Open(cfg); err == nil {
		reopened.Close()
		t.Fatal("expired callback state was silently reopened")
	}
}
