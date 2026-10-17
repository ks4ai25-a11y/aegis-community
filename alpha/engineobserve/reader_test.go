//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package engineobserve

import (
	"aegis.local/alpha/enginetls"
	"aegis.local/alpha/internal/testpki"
	"aegis.local/source"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const validInfo = `{"ID":"unit-engine","OSType":"linux","Architecture":"amd64","AdditionalMetadata":{"ignored":true}}`

type fixture struct {
	config   Config
	observer testpki.Fixture
	broker   testpki.Fixture
	mu       sync.Mutex
	requests []string
	server   *http.Server
}

func target(n int) Target {
	return Target{Name: fmt.Sprintf("aegis-scan-%032x", n), ID: fmt.Sprintf("%064x", n)}
}

// This is an isolated TLS protocol server, not a Docker daemon or proof of
// controller fencing/release. Only guarded hosted acceptance uses a daemon.
func newFixture(t *testing.T, mode string) *fixture {
	t.Helper()
	root, err := os.MkdirTemp("", "aegis-observe-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	broker := testpki.New(t, filepath.Join(root, "broker"), enginetls.Broker)
	observer := broker.AdditionalClientAt(t, filepath.Join(root, "observer"), enginetls.Observer, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	b, err := enginetls.Load(broker.Directory, enginetls.Broker)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "unix://" + filepath.Join(root, "engine.sock")
	f := &fixture{broker: broker, observer: observer, config: Config{Endpoint: endpoint, IdentityDirectory: observer.Directory, BrokerCertificatePEM: broker.Client, ExpectedEngine: source.Hash([]byte("aegis-scanner-mtls-engine-v1\n" + endpoint + "\nunit-engine\n" + b.Digest))}}
	listener, err := net.Listen("unix", strings.TrimPrefix(endpoint, "unix://"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(broker.CA)
	serverCert := broker.Server
	if mode == "foreign-server-ca" {
		serverCert = testpki.New(t, filepath.Join(root, "foreign-server"), enginetls.Broker).Server
	}
	f.server = &http.Server{ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, req.Method+" "+req.URL.RequestURI())
		n := len(f.requests)
		f.mu.Unlock()
		if req.TLS == nil || req.TLS.Version != tls.VersionTLS13 || req.TLS.ServerName != enginetls.ServerName || len(req.TLS.PeerCertificates) != 1 || req.TLS.PeerCertificates[0].Subject.CommonName != enginetls.Observer || req.ProtoMajor != 1 || req.Method != http.MethodGet || req.URL.RawQuery != "" {
			t.Error("observer TLS/request boundary violated")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if mode == "stall" {
			<-req.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/v1.55/info" {
			body := validInfo
			switch mode {
			case "changed-engine":
				if n > 1 {
					body = strings.ReplaceAll(body, "unit-engine", "other-engine")
				}
			case "wrong-engine":
				body = strings.ReplaceAll(body, "unit-engine", "other-engine")
			case "duplicate-info":
				body = `{"ID":"unit-engine","ID":"unit-engine","OSType":"linux","Architecture":"amd64"}`
			case "alias-info":
				body = `{"ID":"unit-engine","id":"unit-engine","OSType":"linux","Architecture":"amd64"}`
			case "case-info":
				body = strings.ReplaceAll(body, `"ID"`, `"Id"`)
			case "trailing-info":
				body += `{}`
			case "null-info":
				body = `null`
			case "windows":
				body = strings.ReplaceAll(body, "linux", "windows")
			case "architecture":
				body = strings.ReplaceAll(body, "amd64", "riscv64")
			case "oversized-info":
				body = strings.Repeat(" ", 65537)
			case "info-status":
				w.WriteHeader(http.StatusForbidden)
			}
			io.WriteString(w, body)
			return
		}
		if !strings.HasPrefix(req.URL.Path, "/v1.55/containers/") || !strings.HasSuffix(req.URL.Path, "/json") {
			t.Error("unexpected observer endpoint")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		status, body := http.StatusNotFound, `{"message":"No such container"}`
		switch mode {
		case "id-present":
			if n == 2 {
				status = http.StatusOK
			}
		case "name-present":
			if n == 3 {
				status = http.StatusOK
			}
		case "inspect-denied":
			status = http.StatusForbidden
		case "inspect-error":
			status = http.StatusInternalServerError
		case "redirect":
			w.Header().Set("Location", "http://127.0.0.1:1/private-redirect-canary")
			status = http.StatusTemporaryRedirect
		case "html-404":
			body = "404 page not found"
		case "router-404":
			body = `{"message":"page not found"}`
		case "empty-404":
			body = ""
		case "null-message":
			body = `{"message":null}`
		case "alias-message":
			body = `{"Message":"missing"}`
		case "duplicate-message":
			body = `{"message":"missing","message":"missing"}`
		case "trailing-message":
			body += ` {}`
		case "oversized-404":
			body = `{"message":"` + strings.Repeat("x", 65536) + `"}`
		case "compressed-404":
			w.Header().Set("Content-Encoding", "gzip")
		case "truncated-404":
			w.Header().Set("Content-Length", "1024")
		case "withdraw-during-response":
			if err := os.Remove(filepath.Join(observer.Directory, "client.key")); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	})}
	go f.server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}}))
	t.Cleanup(func() { f.server.Close() })
	return f
}

func (f *fixture) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func openReader(t *testing.T, f *fixture) *Reader {
	t.Helper()
	r, err := Open(f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestObserverChecksBothExactIdentitiesWithoutBrokerKeyOrAmbientConfig(t *testing.T) {
	f := newFixture(t, "")
	if err := os.RemoveAll(f.broker.Directory); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"DOCKER_HOST": "tcp://private-engine-canary:2375", "DOCKER_CONTEXT": "ambient-canary", "DOCKER_TLS_VERIFY": "0", "DOCKER_CERT_PATH": "/missing-canary", "HTTPS_PROXY": "http://127.0.0.1:1", "DOCKER_API_VERSION": "0.1", "AEGIS_SCANNER_ENGINE_TLS_DIR": "/missing-broker-canary"} {
		t.Setenv(name, value)
	}
	r := openReader(t, f)
	if err := r.VerifyAbsent(context.Background(), []Target{target(1), target(2)}); err != nil {
		t.Fatal(err)
	}
	expected := []string{"GET /v1.55/info"}
	for _, target := range []Target{target(1), target(2)} {
		expected = append(expected, "GET /v1.55/containers/"+target.ID+"/json", "GET /v1.55/containers/"+target.Name+"/json")
	}
	expected = append(expected, "GET /v1.55/info")
	if strings.Join(f.calls(), "\n") != strings.Join(expected, "\n") {
		t.Fatal("observer did not restrict exact allocation read sequence")
	}
}

func TestObserverChecksNameOnlyForUncreatedLaunch(t *testing.T) {
	f := newFixture(t, "")
	r := openReader(t, f)
	uncreated := Target{Name: target(2).Name}
	if err := r.VerifyAbsent(context.Background(), []Target{target(1), uncreated}); err != nil {
		t.Fatal(err)
	}
	expected := []string{"GET /v1.55/info", "GET /v1.55/containers/" + target(1).ID + "/json", "GET /v1.55/containers/" + target(1).Name + "/json", "GET /v1.55/containers/" + uncreated.Name + "/json", "GET /v1.55/info"}
	if strings.Join(f.calls(), "\n") != strings.Join(expected, "\n") {
		t.Fatal("name-only target read an unexpected sequence", f.calls())
	}
	if r.VerifyAbsent(context.Background(), []Target{uncreated, uncreated}) != ErrUnconfirmed {
		t.Fatal("duplicate name-only target accepted")
	}
}

func TestObserverRefusesUnconfirmedScopeOrAbsence(t *testing.T) {
	for _, mode := range []string{"wrong-engine", "changed-engine", "duplicate-info", "alias-info", "case-info", "trailing-info", "null-info", "windows", "architecture", "oversized-info", "info-status", "id-present", "name-present", "inspect-denied", "inspect-error", "redirect", "html-404", "router-404", "empty-404", "null-message", "alias-message", "duplicate-message", "trailing-message", "oversized-404", "compressed-404", "truncated-404", "withdraw-during-response", "foreign-server-ca"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode)
			r := openReader(t, f)
			if err := r.VerifyAbsent(context.Background(), []Target{target(1)}); err != ErrUnconfirmed || strings.Contains(err.Error(), "canary") {
				t.Fatal("uncertain engine result became absence or exposed private detail")
			}
		})
	}
}

func TestObserverWithdrawalAndReplacementRefuseCachedTLSConnection(t *testing.T) {
	f := newFixture(t, "")
	r := openReader(t, f)
	if err := r.VerifyAbsent(context.Background(), []Target{target(1)}); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls())
	if err := os.Remove(filepath.Join(f.observer.Directory, "client.key")); err != nil {
		t.Fatal(err)
	}
	if r.VerifyAbsent(context.Background(), []Target{target(1)}) == nil || len(f.calls()) != before {
		t.Fatal("cached TLS connection survived observer withdrawal")
	}
	replacement := f.broker.AdditionalClientAt(t, filepath.Join(filepath.Dir(f.observer.Directory), "replacement"), enginetls.Observer, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	for name, data := range map[string][]byte{"ca.pem": replacement.CA, "client.pem": replacement.Client, "client.key": replacement.Key} {
		if err := os.WriteFile(filepath.Join(f.observer.Directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if r.VerifyAbsent(context.Background(), []Target{target(1)}) == nil || len(f.calls()) != before {
		t.Fatal("replacement observer acquired cached identity")
	}
}

func TestObserverRefusesInvalidMembershipBeforeAnyRequest(t *testing.T) {
	f := newFixture(t, "")
	r := openReader(t, f)
	for _, targets := range [][]Target{nil, {target(1), target(1)}, {{Name: "untracked", ID: target(1).ID}}, {{Name: target(1).Name, ID: "short"}}, {target(1), target(2), target(3), target(4), target(5), target(6), target(7)}} {
		if r.VerifyAbsent(context.Background(), targets) == nil {
			t.Fatal("invalid allocation membership accepted")
		}
	}
	if len(f.calls()) != 0 {
		t.Fatal("invalid allocation caused engine traffic")
	}
}

func TestObserverOpenRefusesUnsafeConfigurationWithoutEngineTraffic(t *testing.T) {
	f := newFixture(t, "")
	for _, kind := range []string{"remote", "plaintext", "relative", "noncanonical", "query", "userinfo", "escaped-path", "missing-identity", "broker-private-identity", "observer-public-certificate", "missing-public-certificate", "invalid-engine-digest"} {
		t.Run(kind, func(t *testing.T) {
			c := f.config
			switch kind {
			case "remote":
				c.Endpoint = "https://private-engine-canary:2376"
			case "plaintext":
				c.Endpoint = "tcp://127.0.0.1:2375"
			case "relative":
				c.Endpoint = "unix:engine.sock"
			case "noncanonical":
				c.Endpoint = "unix:///tmp/../tmp/engine.sock"
			case "query":
				c.Endpoint += "?"
			case "userinfo":
				c.Endpoint = "unix://canary@/tmp/engine.sock"
			case "escaped-path":
				c.Endpoint = "unix:///tmp/engine%2esock"
			case "missing-identity":
				c.IdentityDirectory = "/missing-private-observer-canary"
			case "broker-private-identity":
				c.IdentityDirectory = f.broker.Directory
			case "observer-public-certificate":
				c.BrokerCertificatePEM = f.observer.Client
			case "missing-public-certificate":
				c.BrokerCertificatePEM = nil
			case "invalid-engine-digest":
				c.ExpectedEngine = "unbound"
			}
			r, err := Open(c)
			if r != nil {
				r.Close()
			}
			if err != ErrUnconfirmed {
				t.Fatal("unsafe observer configuration accepted")
			}
		})
	}
	if len(f.calls()) != 0 {
		t.Fatal("invalid configuration contacted engine")
	}
}

func TestObserverCannotSubstituteItsOwnDigestForOriginalBroker(t *testing.T) {
	f := newFixture(t, "")
	i, err := enginetls.Load(f.observer.Directory, enginetls.Observer)
	if err != nil {
		t.Fatal(err)
	}
	f.config.ExpectedEngine = source.Hash([]byte("aegis-scanner-mtls-engine-v1\n" + f.config.Endpoint + "\nunit-engine\n" + i.Digest))
	r := openReader(t, f)
	if r.VerifyAbsent(context.Background(), []Target{target(1)}) != ErrUnconfirmed || len(f.calls()) != 1 {
		t.Fatal("observer identity substituted for original broker engine scope")
	}
}

func TestObserverCloseCancellationAndUnavailableEngine(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		f := newFixture(t, "stall")
		r := openReader(t, f)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if r.VerifyAbsent(ctx, []Target{target(1)}) != ErrUnconfirmed {
			t.Fatal("cancelled observation accepted")
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		f := newFixture(t, "")
		r := openReader(t, f)
		f.server.Close()
		if r.VerifyAbsent(context.Background(), []Target{target(1)}) != ErrUnconfirmed {
			t.Fatal("unavailable engine became absence")
		}
	})
	t.Run("closed", func(t *testing.T) {
		f := newFixture(t, "")
		r := openReader(t, f)
		r.Close()
		r.Close()
		if r.VerifyAbsent(context.Background(), []Target{target(1)}) != ErrUnconfirmed || len(f.calls()) != 0 {
			t.Fatal("closed reader retained authority")
		}
	})
}
