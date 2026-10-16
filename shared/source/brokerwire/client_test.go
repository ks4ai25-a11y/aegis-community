//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package brokerwire

import (
	"aegis.local/source/privateipc"
	"context"
	"encoding/json"
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

func TestDispatchUsesOnlyPrivateUnixAndRejectsRedirectsIncompleteOrOversizedReplies(t *testing.T) {
	for _, kind := range []string{"valid", "redirect", "oversized", "partial", "alias"} {
		t.Run(kind, func(t *testing.T) {
			parent, e := os.MkdirTemp("/tmp", "abc-")
			if e != nil {
				t.Fatal(e)
			}
			parent, _ = filepath.EvalSymlinks(parent)
			defer os.RemoveAll(parent)
			token := filepath.Join(parent, "token")
			if e = privateipc.EnrollToken(token); e != nil {
				t.Fatal(e)
			}
			socket := filepath.Join(parent, "s")
			listener, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			os.Chmod(socket, 0600)
			var external, calls atomic.Int32
			trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { external.Add(1) }))
			defer trap.Close()
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				expected, _ := privateipc.ReadToken(token)
				if r.Method != "POST" || r.URL.Path != RunPath || r.Header.Get("Authorization") != "Bearer "+expected {
					t.Error("invalid private request")
				}
				w.Header().Set("Content-Type", "application/json")
				raw, _ := json.Marshal(Outcome{Schema: "1.0", State: "no_job"})
				switch kind {
				case "redirect":
					w.Header().Set("Location", trap.URL)
					w.WriteHeader(302)
					return
				case "oversized":
					raw = []byte(strings.Repeat(" ", 4097))
				case "partial":
					w.Header().Set("Content-Length", "1000")
				case "alias":
					raw = []byte(strings.Replace(string(raw), `"state":`, `"State":`, 1))
				}
				w.Write(raw)
			})}
			go server.Serve(listener)
			defer server.Close()
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, e := Dispatch(ctx, socket, token)
			if kind == "valid" {
				if e != nil || out.State != "no_job" {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("unsafe reply", kind)
			}
			if external.Load() != 0 || calls.Load() != 1 {
				t.Fatal("private transport escaped", external.Load(), calls.Load())
			}
			os.Remove(token)
			if _, e = Dispatch(context.Background(), socket, token); e == nil || calls.Load() != 1 {
				t.Fatal("withdrawn capability reused")
			}
		})
	}
}
