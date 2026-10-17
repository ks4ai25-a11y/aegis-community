// SPDX-License-Identifier: Apache-2.0
package engineauthz_test

import (
	"aegis.local/alpha/engineobserve"
	"aegis.local/source"
	"context"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// newRealObserver adds only an opaque, private Unix-to-loopback TLS relay to
// the already guarded disposable daemon fixture. It cannot terminate TLS or
// substitute a broker key. This is observation proof, not controller release.
func newRealObserver(t *testing.T, ctx context.Context, root, upstream, engineID string) *engineobserve.Reader {
	t.Helper()
	if os.Getenv("AEGIS_REAL_ENGINE_AUTHZ_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() <= 0 {
		t.Fatal("disposable unprivileged Linux CI observer only")
	}
	host, _, err := net.SplitHostPort(upstream)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("fixed loopback TLS upstream required")
	}
	identityDir := filepath.Join(root, "reader-identity")
	if err = os.Mkdir(identityDir, 0700); err != nil {
		t.Fatal("private observer directory unavailable")
	}
	for src, dst := range map[string]string{"ca.pem": "ca.pem", "observer.pem": "client.pem", "observer.key": "client.key"} {
		b, err := os.ReadFile(filepath.Join(root, "tls", src))
		if err != nil || os.WriteFile(filepath.Join(identityDir, dst), b, 0600) != nil {
			t.Fatal("private observer identity unavailable")
		}
	}
	brokerPublic, err := os.ReadFile(filepath.Join(root, "tls", "broker.pem"))
	if err != nil {
		t.Fatal("public broker certificate unavailable")
	}
	ca, err := os.ReadFile(filepath.Join(identityDir, "ca.pem"))
	if err != nil {
		t.Fatal("observer CA unavailable")
	}
	caBlock, _ := pem.Decode(ca)
	brokerBlock, _ := pem.Decode(brokerPublic)
	if caBlock == nil || brokerBlock == nil {
		t.Fatal("fixture public certificates invalid")
	}
	brokerDigest := source.Hash(append(append([]byte("aegis-scanner-engine-mtls-identity-v1\n"), caBlock.Bytes...), brokerBlock.Bytes...))
	path := filepath.Join(root, "reader.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal("private observer relay unavailable")
	}
	relayCtx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	var copies sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[local] = true
			mu.Unlock()
			copies.Add(1)
			go func() {
				defer copies.Done()
				defer func() { local.Close(); mu.Lock(); delete(connections, local); mu.Unlock() }()
				remote, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(relayCtx, "tcp", upstream)
				if err != nil {
					return
				}
				defer remote.Close()
				local.SetDeadline(time.Now().Add(30 * time.Second))
				remote.SetDeadline(time.Now().Add(30 * time.Second))
				done := make(chan struct{})
				go func() { io.Copy(remote, local); remote.Close(); close(done) }()
				io.Copy(local, remote)
				local.Close()
				remote.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-accepted
		mu.Lock()
		for connection := range connections {
			connection.Close()
		}
		mu.Unlock()
		copies.Wait()
	})
	endpoint := "unix://" + path
	expected := source.Hash([]byte("aegis-scanner-mtls-engine-v1\n" + endpoint + "\n" + engineID + "\n" + brokerDigest))
	reader, err := engineobserve.Open(engineobserve.Config{Endpoint: endpoint, IdentityDirectory: identityDir, ExpectedEngine: expected, BrokerCertificatePEM: brokerPublic})
	if err != nil {
		t.Fatal("independent TLS observer configuration refused")
	}
	t.Cleanup(reader.Close)
	return reader
}
