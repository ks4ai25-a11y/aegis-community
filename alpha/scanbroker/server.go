// SPDX-License-Identifier: BUSL-1.1
// Package scanbroker owns the privileged fixed scanner orchestrator. Its client
// supplies no execution arguments and receives no enrollment/lease capability.
package scanbroker

import (
	"aegis.local/alpha/worker"
	"aegis.local/source/brokerwire"
	"aegis.local/source/privateipc"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Worker     worker.Config
	Credential string
	Run        func(context.Context) (worker.Report, error)
}

type runGate struct {
	mu       sync.Mutex
	stopping bool
	active   sync.WaitGroup
}

func (g *runGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopping {
		return false
	}
	g.active.Add(1)
	return true
}
func (g *runGate) stop()               { g.mu.Lock(); g.stopping = true; g.mu.Unlock() }
func (s Server) Handler() http.Handler { return s.handler(&runGate{}) }
func (s Server) handler(gate *runGate) http.Handler {
	slot := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		fail := func(status int) { w.WriteHeader(status); io.WriteString(w, `{"error":"BROKER_REQUEST_REFUSED"}`) }
		if r.Method != "POST" || r.URL.Path != brokerwire.RunPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Host != "unix" || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || len(r.TransferEncoding) != 0 {
			fail(403)
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			fail(401)
			return
		}
		token := strings.TrimPrefix(values[0], "Bearer ")
		expected, e := privateipc.ReadToken(s.Credential)
		if s.Run == nil {
			workerToken, readErr := privateipc.ReadToken(s.Worker.Credential)
			if readErr != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(workerToken)) == 1 {
				fail(401)
				return
			}
		}
		if e != nil || !privateipc.TokenPattern.MatchString(token) || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			fail(401)
			return
		}
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 512))
		_ = controller.SetReadDeadline(time.Time{})
		if e != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte(`{}`)) {
			fail(400)
			return
		}
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			fail(409)
			return
		}
		if !gate.enter() {
			fail(503)
			return
		}
		defer gate.active.Done()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()
		run := s.Run
		if run == nil {
			if !s.Worker.RequireEngineBinding || s.Worker.ExpectedBrokerID == "" {
				fail(503)
				return
			}
			run = s.Worker.RunOnce
		}
		report, runErr := run(ctx)
		if runErr != nil && (report.State == "no_job" || report.State == "completed" || report.State == "completed_partial" || report.State == "completed_stale_db") {
			fail(503)
			return
		}
		out := brokerwire.Outcome{Schema: "1.0", State: report.State, Job: report.Job, Request: report.Request, Receipts: len(report.Receipts)}
		if report.Result != nil {
			out.Result = report.Result.Digest
		}
		if !out.Valid() {
			fail(503)
			return
		}
		json.NewEncoder(w).Encode(out)
	})
}

// HTTP may stop accepting connections before active cleanup has joined. Keep
// the private listener's process lock held until Serve returns to its caller.
type acceptingListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}
type boundedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *boundedConn) Close() error {
	var e error
	c.once.Do(func() { e = c.Conn.Close(); c.release() })
	return e
}
func (l *acceptingListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	conn, e := l.Listener.Accept()
	if e != nil {
		<-l.slots
		return nil, e
	}
	return &boundedConn{Conn: conn, release: func() { <-l.slots }}, nil
}
func (l *acceptingListener) Close() error {
	var e error
	l.once.Do(func() { close(l.done); e = l.Listener.(interface{ CloseSocket() error }).CloseSocket() })
	return e
}
func (s Server) Serve(ctx context.Context, socket string) error {
	if os.Geteuid() <= 0 || !s.Worker.RequireEngineBinding || s.Worker.ExpectedBrokerID == "" {
		return errors.New("bound broker configuration required")
	}
	controlToken, e := privateipc.ReadToken(s.Credential)
	if e != nil {
		return e
	}
	workerToken, e := privateipc.ReadToken(s.Worker.Credential)
	if e != nil || subtle.ConstantTimeCompare([]byte(controlToken), []byte(workerToken)) == 1 {
		return errors.New("distinct private broker role credentials required")
	}

	listener, e := privateipc.Listen(socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	gate := &runGate{}
	runContext, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	server := &http.Server{Handler: s.handler(gate), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 16 * time.Minute, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(_ net.Listener) context.Context { return runContext }}
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			gate.stop()
			server.Close()
		case <-stopped:
		}
	}()
	e = server.Serve(&acceptingListener{Listener: listener, slots: make(chan struct{}, 8), done: make(chan struct{})})
	gate.stop()
	cancelRun()
	server.Close()
	joined := make(chan struct{})
	go func() { gate.active.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(20 * time.Second):
		return errors.New("broker shutdown remains uncertain")
	}

	if ctx.Err() != nil || errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
