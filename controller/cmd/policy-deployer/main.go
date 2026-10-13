// SPDX-License-Identifier: Apache-2.0
// The deployer has the gateway socket, but no controller database or network.
package main

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func main() {
	root := "/var/lib/deployer"
	socket := "/run/deployer/deployer.sock"
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		panic(err)
	}
	// Only this process owns this socket in the single-instance Compose service.
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		panic(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		panic(err)
	}
	m := &policy.Manager{Root: filepath.Join(root, "policies"), Binary: "/usr/local/bin/caddy", Socket: "/run/gateway/admin.sock", Origin: "demo-origin:8080", Listen: ":8080", Log: "/var/log/aegis/events.jsonl"}
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		deny := func(status int, msg string) {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
		}
		if r.Method != "POST" {
			deny(405, "POST required")
			return
		}
		var in struct {
			Policy   domain.Policy `json:"policy"`
			Expected string        `json:"expected_revision"`
		}
		if auth.Decode(r, &in) != nil {
			deny(400, "invalid typed request")
			return
		}
		p := in.Policy
		if !mu.TryLock() {
			deny(429, "deployment operation in progress")
			return
		}
		defer mu.Unlock()
		err = nil
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var digest string
		switch r.URL.Path {
		case "/status":
			digest, err = m.Active(ctx)
		case "/validate":
			digest, err = m.Prepare(ctx, p)
		case "/apply":
			var active string
			active, err = m.Active(ctx)
			if err == nil && active != in.Expected {
				deny(409, "stale gateway parent")
				return
			}
			if err == nil {
				digest, err = m.Prepare(ctx, p)
			}
			if err == nil {
				err = m.Reload(ctx, p)
			}
			if err == nil {
				err = policy.Atomic(filepath.Join(root, "active.Caddyfile"), []byte(policy.Render(p, m.Origin, m.Listen, m.Socket, m.Log)))
			}
			// Persistence errors are indeterminate. The controller freezes rather than claiming success.
		default:
			deny(404, "operation not supported")
			return
		}
		if err != nil {
			deny(503, "gateway operation could not be confirmed")
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"digest": digest})
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	fmt.Println("Typed policy deployer ready")
	if err := server.Serve(ln); err != nil {
		panic(err)
	}
}
