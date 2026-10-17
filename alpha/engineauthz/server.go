// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Handler is reachable only through the daemon's private plugin socket. Never
// expose this protocol through a TCP listener or a controller/browser route.
func (p *Policy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := deny()
		if r.Method == "POST" && r.URL.RawPath == "" && r.URL.RawQuery == "" && !r.URL.ForceQuery && r.Header.Get("Content-Encoding") == "" {
			raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 262144))
			if e == nil {
				if r.URL.Path == "/Plugin.Activate" {
					var object map[string]json.RawMessage
					if len(bytes.TrimSpace(raw)) == 0 || strict(raw, &object, 262144) == nil && object != nil && len(object) == 0 {
						io.WriteString(w, `{"Implements":["authz"]}`)
						return
					}
				} else if r.URL.Path == "/AuthZPlugin.AuthZReq" || r.URL.Path == "/AuthZPlugin.AuthZRes" {
					var request Request
					if strict(raw, &request, 262144) == nil {
						if r.URL.Path == "/AuthZPlugin.AuthZReq" {
							result = p.AuthorizeRequestContext(r.Context(), request)
						} else {
							result = p.AuthorizeResponseContext(r.Context(), request)
						}
					}
				}
			}
		}
		// A valid Docker plugin reply always carries Allow:false on any refusal.
		// Do not reflect request data, source paths, principals or engine errors.
		_ = json.NewEncoder(w).Encode(result)
	})
}

type connections struct {
	net.Listener
	slots chan struct{}
}
type connection struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *connection) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return e
}
func (l *connections) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &connection{Conn: c, slots: l.slots}, nil
		default:
			c.Close()
		}
	}
}

// Serve never opens an engine connection. Every allowed mutation must already
// have been persisted by AuthorizeRequest before a positive reply is written.
func (p *Policy) Serve(ctx context.Context, listener net.Listener) error {
	server := &http.Server{Handler: p.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	e := server.Serve(&connections{listener, make(chan struct{}, 8)})
	close(done)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
