//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package executor

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/enginetls"
	"aegis.local/alpha/internal/testpki"
	"aegis.local/source"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tlsSDKFixture(t *testing.T) (string, testpki.Fixture, *atomic.Int32) {
	t.Helper()
	dir, e := os.MkdirTemp("", "aegis-mtls-")
	if e != nil {
		t.Fatal(e)
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := testpki.New(t, filepath.Join(dir, "client"), enginetls.Broker)
	path := filepath.Join(dir, "engine.sock")
	listener, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(f.CA)
	var count atomic.Int32
	server := &http.Server{ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.ServerName != enginetls.ServerName || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != enginetls.Broker || r.ProtoMajor != 1 {
			t.Error("unrestricted TLS metadata request")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.55/info":
			io.WriteString(w, validMetadataInfo)
		case "/v1.55/images/" + metadataTool().Image + "/json":
			io.WriteString(w, validMetadataImage(metadataTool()))
		default:
			t.Error("unexpected engine request", r.Method, r.URL.Path)
			w.WriteHeader(403)
		}
	})}
	go server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.Server}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}}))
	t.Cleanup(func() { server.Close() })
	t.Setenv("AEGIS_SCANNER_ENGINE_TLS_DIR", f.Directory)
	t.Setenv("DOCKER_HOST", "unix://"+path)
	t.Setenv("DOCKER_CONTEXT", "")
	return "unix://" + path, f, &count
}
func TestTLSUnixMetadataBindsCertificatesAndIgnoresAmbientDockerTLS(t *testing.T) {
	endpoint, f, count := tlsSDKFixture(t)
	t.Setenv("DOCKER_TLS_VERIFY", "0")
	t.Setenv("DOCKER_CERT_PATH", "/missing")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "0.1")
	p, e := preflightSDK(context.Background(), endpoint, metadataTool(), source.Hash([]byte("lock")))
	if e != nil {
		t.Fatal(e)
	}
	identity, e := enginetls.Load(f.Directory, enginetls.Broker)
	if e != nil {
		t.Fatal(e)
	}
	expected := source.Hash([]byte("aegis-scanner-mtls-engine-v1\n" + endpoint + "\nfixture-engine\n" + identity.Digest))
	if p.Engine != expected || p.Engine == source.Hash([]byte(endpoint+"\nfixture-engine")) || p.Backend != "mtls-unix-sdk-1.55" || p.engineTLSIdentity != identity.Digest || count.Load() != 2 {
		t.Fatal("transport identity not bound", p)
	}
	digest, e := ConfiguredEngineDigest(context.Background())
	if e != nil || digest != p.Engine {
		t.Fatal("binding helper disagrees", e)
	}
}
func TestTLSWithdrawalRefusesCachedConnectionBeforeAnotherRPC(t *testing.T) {
	endpoint, f, count := tlsSDKFixture(t)
	active := &responseCapture{operation: "info"}
	req, res := metadataHooks("", &active)
	c, e := newRestrictedEngineSDK(endpoint, req, res)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	// Use the exact already-created HTTP client so a keep-alive connection could
	// otherwise retain authority after the private key is withdrawn.
	call := func() error {
		r, _ := http.NewRequestWithContext(context.WithValue(context.Background(), captureKey{}, active), "GET", "https://docker/v1.55/info", nil)
		response, e := c.http.Do(r)
		if e == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		return e
	}
	if call() != nil || count.Load() != 1 {
		t.Fatal("initial TLS request")
	}
	os.Remove(filepath.Join(f.Directory, "client.key"))
	if call() == nil || count.Load() != 1 {
		t.Fatal("cached connection bypassed credential withdrawal")
	}
}
func TestTLSMissingIdentityAndPlaintextCannotDowngrade(t *testing.T) {
	_, _, count := tlsSDKFixture(t)
	t.Setenv("AEGIS_SCANNER_ENGINE_TLS_DIR", "/missing-private-engine-identity")
	if _, e := ConfiguredEngineDigest(context.Background()); e == nil || count.Load() != 0 {
		t.Fatal("missing identity silently fell back")
	}
	if _, e := (Config{}).Run(context.Background(), "bandit", "a", "r", source.Snapshot{}); e == nil {
		t.Fatal("TLS mode selected CLI backend")
	}
}
func TestTLSIdentityChangeBeforeCreateDoesNotAllocateAttempt(t *testing.T) {
	endpoint, f, count := tlsSDKFixture(t)
	p, e := preflightSDK(context.Background(), endpoint, metadataTool(), source.Hash([]byte("lock")))
	if e != nil {
		t.Fatal(e)
	}
	// A different expected identity must fail before Begin/create even when the
	// newly configured identity would be valid for a TLS handshake.
	cfg := Config{EngineJournalRoot: filepath.Join(filepath.Dir(f.Directory), "journal"), engineTLSIdentity: source.Hash([]byte("other-identity"))}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	options := sdkCreateOptions(metadataTool(), "aegis-scan-"+strings.Repeat("a", 32), filepath.Dir(f.Directory), "", filepath.Dir(f.Directory), 30, time.Now().Add(time.Minute))
	out := cfg.runEngineSDK(ctx, endpoint, p.Engine, options.Name, options, io.Discard, io.Discard, cancel)
	if out.err == nil || out.cleanup || count.Load() != 2 {
		t.Fatal("changed TLS scope reached engine mutation")
	}
	observed, e := enginejournal.ReadObservation(cfg.EngineJournalRoot, p.Engine)
	if e != nil || observed.Attempts != 0 {
		t.Fatal("changed identity allocated an attempt", e)
	}
}

func TestTLSModeNeverFallsBackToPlaintextUnixHTTP(t *testing.T) {
	_, _, _ = tlsSDKFixture(t)
	var plaintext atomic.Int32
	endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		plaintext.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, validMetadataInfo)
	})
	t.Setenv("DOCKER_HOST", endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, e := ConfiguredEngineDigest(ctx); e == nil || plaintext.Load() != 0 {
		t.Fatal("TLS identity fell back to plaintext")
	}
}

type attachTransport func(*http.Request) (*http.Response, error)

func (f attachTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTLSAttachUsesCanonicalOutputOnlyUpgrade(t *testing.T) {
	seen := false
	c := &scannerEngineClient{scheme: "https", http: &http.Client{Transport: attachTransport(func(r *http.Request) (*http.Response, error) {
		seen = true
		if r.URL.Scheme != "https" || r.Method != "POST" || r.URL.RawQuery != "stderr=1&stdout=1&stream=1" || r.Header.Get("Upgrade") != "tcp" || r.Header.Get("Connection") != "Upgrade" || r.Body != nil {
			t.Fatal("attach differs from finite daemon authorization contract")
		}
		return &http.Response{StatusCode: 101, Header: http.Header{"Upgrade": []string{"tcp"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}}
	body, e := c.attach(context.Background(), strings.Repeat("a", 64))
	if e != nil || !seen {
		t.Fatal("canonical TLS attach failed", e)
	}
	body.Close()
}
