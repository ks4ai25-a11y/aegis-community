//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scanbroker

import (
	"aegis.local/alpha/worker"
	"aegis.local/source/brokerwire"
	"aegis.local/source/privateipc"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setup(t *testing.T) (string, string, string) {
	t.Helper()
	p, e := os.MkdirTemp("/tmp", "asb-")
	if e != nil {
		t.Fatal(e)
	}
	p, _ = filepath.EvalSymlinks(p)
	t.Cleanup(func() { os.RemoveAll(p) })
	path := filepath.Join(p, "token")
	if e = privateipc.EnrollToken(path); e != nil {
		t.Fatal(e)
	}
	token, e := privateipc.ReadToken(path)
	if e != nil {
		t.Fatal(e)
	}
	return p, path, token
}
func req(token, body string) *http.Request {
	r := httptest.NewRequest("POST", "http://unix"+brokerwire.RunPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
func TestBrokerFiniteRPCRejectsParametersBrowserAndRawDaemonPaths(t *testing.T) {
	_, path, token := setup(t)
	var calls atomic.Int32
	s := Server{Credential: path, Run: func(context.Context) (worker.Report, error) {
		calls.Add(1)
		return worker.Report{Schema: "1.0", State: "no_job"}, nil
	}}
	h := s.Handler()
	for _, kind := range []string{"valid", "command", "owner", "null", "trailing", "large", "method", "path", "query", "cookie", "origin", "host", "duplicate-auth", "wrong-auth", "encoding"} {
		t.Run(kind, func(t *testing.T) {
			r := req(token, `{}`)
			expect := 403
			switch kind {
			case "valid":
				expect = 200
			case "command":
				r = req(token, `{"command":"execute"}`)
				expect = 400
			case "owner":
				r = req(token, `{"owner_id":"other"}`)
				expect = 400
			case "null":
				r = req(token, `null`)
				expect = 400
			case "trailing":
				r = req(token, `{} {}`)
				expect = 400
			case "large":
				r = req(token, strings.Repeat(" ", 513))
				expect = 400
			case "method":
				r.Method = "GET"
			case "path":
				r.URL.Path = "/v1.55/containers/create"
			case "query":
				r.URL.RawQuery = "force=true"
			case "cookie":
				r.Header.Set("Cookie", "session=unrelated")
			case "origin":
				r.Header.Set("Origin", "https://browser.invalid")
			case "host":
				r.Host = "external.invalid"
			case "duplicate-auth":
				r.Header.Add("Authorization", "Bearer "+token)
				expect = 401
			case "wrong-auth":
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
				expect = 401
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != expect {
				t.Fatal(kind, w.Code, expect)
			}
			if expect == 200 {
				if _, e := brokerwire.Decode(w.Body.Bytes()); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("refused request reached worker", calls.Load())
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(token, `{}`))
	if w.Code != 401 || calls.Load() != 1 {
		t.Fatal("deleted capability retained")
	}
}
func TestBrokerSerializesAndDoesNotReportSuccessOnWorkerError(t *testing.T) {
	_, path, token := setup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	s := Server{Credential: path, Run: func(context.Context) (worker.Report, error) {
		close(entered)
		<-release
		return worker.Report{Schema: "1.0", State: "no_job"}, errors.New("failure")
	}}
	h := s.Handler()
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, req(token, `{}`)); done <- w.Code }()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(token, `{}`))
	if w.Code != 409 {
		t.Fatal("concurrent dispatch")
	}
	close(release)
	if code := <-done; code != 503 {
		t.Fatal("error became success", code)
	}
}
func TestBrokerShutdownJoinsCancelledWorkBeforeReleasingSocketLock(t *testing.T) {
	parent, path, _ := setup(t)
	socket := filepath.Join(parent, "s")
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerCredential := filepath.Join(parent, "worker-token")
	if e := privateipc.EnrollToken(workerCredential); e != nil {
		t.Fatal(e)
	}
	s := Server{Credential: path, Worker: worker.Config{Credential: workerCredential, RequireEngineBinding: true, ExpectedBrokerID: "broker"}, Run: func(ctx context.Context) (worker.Report, error) {
		close(entered)
		<-ctx.Done()
		<-release
		return worker.Report{Schema: "1.0", State: "not_claimed"}, ctx.Err()
	}}
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Serve(ctx, socket) }()
	for i := 0; i < 100; i++ {
		if privateipc.ValidateSocket(socket) == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	clientDone := make(chan struct{})
	go func() { brokerwire.Dispatch(context.Background(), socket, path); close(clientDone) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatch not started")
	}
	cancel()
	time.Sleep(30 * time.Millisecond)
	if l, e := privateipc.Listen(socket); e == nil {
		l.Close()
		t.Fatal("new broker acquired lock during cleanup")
	}
	select {
	case <-serverDone:
		t.Fatal("shutdown abandoned work")
	default:
	}
	close(release)
	select {
	case e := <-serverDone:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not join")
	}
	<-clientDone
	next, e := privateipc.Listen(socket)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
}

func TestBrokerBoundsAcceptedConnections(t *testing.T) {
	parent, _, _ := setup(t)
	socket := filepath.Join(parent, "bounded")
	raw, e := privateipc.Listen(socket)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	listener := &acceptingListener{Listener: raw, slots: make(chan struct{}, 2), done: make(chan struct{})}
	defer listener.Close()
	accepted := make(chan net.Conn, 3)
	go func() {
		for i := 0; i < 3; i++ {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			accepted <- c
		}
	}()
	clients := []net.Conn{}
	for i := 0; i < 3; i++ {
		c, e := net.Dial("unix", socket)
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	first, second := <-accepted, <-accepted
	defer second.Close()
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("connection budget exceeded")
	case <-time.After(30 * time.Millisecond):
	}
	first.Close()
	select {
	case third := <-accepted:
		third.Close()
	case <-time.After(time.Second):
		t.Fatal("connection slot not released")
	}
}

func TestBrokerRefusesAliasedRoleCapabilitiesBeforeListening(t *testing.T) {
	parent, control, _ := setup(t)
	workerToken := filepath.Join(parent, "copied-worker")
	raw, e := os.ReadFile(control)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(workerToken, raw, 0600); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(parent, "alias-socket")
	s := Server{Credential: control, Worker: worker.Config{RequireEngineBinding: true, ExpectedBrokerID: "broker", Credential: workerToken}}
	if e = s.Serve(context.Background(), socket); e == nil {
		t.Fatal("same capability accepted for both roles")
	}
	if _, e = os.Stat(socket); !os.IsNotExist(e) {
		t.Fatal("aliased server started")
	}
}
