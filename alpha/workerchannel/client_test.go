//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"aegis.local/source"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, h http.Handler) (*Client, string) {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "awc-")
	if e != nil {
		t.Fatal(e)
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "worker.sock")
	listener, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(sock, 0600)
	server := &http.Server{Handler: h}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	cred := filepath.Join(dir, "credential")
	os.WriteFile(cred, []byte(strings.Repeat("a", 64)+"\n"), 0600)
	c, e := New(sock, cred, "owner-a", source.Hash([]byte("pins")))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, cred
}
func claim() Lease {
	m := source.Map{Schema: "1.0", App: "app_demo", SourceRef: "mounted-asset:fixture", Files: []source.File{}, Routes: []source.Route{}, Extractors: []source.Extractor{}, Frameworks: []string{}, Models: []string{}, SensitiveOps: []string{}, AuthBoundaries: []string{}, Unknowns: []string{}}
	b, _ := json.Marshal(m)
	m.Digest = source.Hash(b)
	in := Input{Schema: "1.0", App: "app_demo", Repository: "repository-a", MapDigest: m.Digest, Mode: "repo_offline", Tools: []string{"bandit"}, Duration: 120}
	j := Job{Schema: "1.0", ID: "019b827e-2fa1-7fd1-b9a2-ef8b5e2b5555", Owner: "owner-a", Input: in, LockDigest: source.Hash([]byte("pins")), State: "running", Created: time.Now().UTC().Format(time.RFC3339Nano), Expires: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)}
	b, _ = json.Marshal(struct {
		Owner string `json:"owner_id"`
		Input Input  `json:"input"`
		Lock  string `json:"tool_lock_digest"`
	}{j.Owner, in, j.LockDigest})
	j.RequestDigest = source.Hash(b)
	return Lease{Job: j, Map: m, Token: strings.Repeat("b", 64), Deadline: time.Now().Add(time.Minute).UTC()}
}
func wire(l Lease) map[string]any {
	return map[string]any{"schema_version": "1.0", "launch_protocol": "1.0", "job": l.Job, "application_map": l.Map, "lease_token": l.Token, "deadline": l.Deadline}
}
func TestProtocolLifecycle(t *testing.T) {
	l := claim()
	var mu sync.Mutex
	calls := map[string]int{}
	c, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
			t.Error("private request envelope changed")
			w.WriteHeader(403)
			return
		}
		op := strings.TrimPrefix(r.URL.Path, "/internal/v1/scanner/")
		mu.Lock()
		calls[op]++
		mu.Unlock()
		switch op {
		case "claim":
			json.NewEncoder(w).Encode(wire(l))
		case "identity":
			json.NewEncoder(w).Encode(Identity{"worker-a", "owner-a", "active", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339Nano)})
		case "guard", "fail":
			var request leaseRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Job != l.Job.ID || request.Digest != l.Job.RequestDigest || request.Token != l.Token {
				t.Error("lease request binding changed")
				w.WriteHeader(403)
				return
			}
			if op == "guard" {
				json.NewEncoder(w).Encode(map[string]string{"state": "running"})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"state": "tool_error", "cleanup_required": true})
			}
		default:
			w.WriteHeader(404)
		}
	}))
	ctx := context.Background()
	if _, e := c.Identity(ctx); e != nil {
		t.Fatal(e)
	}
	got, e := c.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Guard(ctx, got); e != nil {
		t.Fatal(e)
	}
	if e = c.Fail(ctx, got, "SOURCE_CAPTURE_FAILED"); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), got.Token) {
		t.Fatal("lease serialization exported capability")
	}
	if e = c.Fail(ctx, got, "raw secret error"); e == nil {
		t.Fatal("accepted arbitrary failure")
	}
	os.Remove(cred)
	if _, e = c.Claim(ctx); e == nil {
		t.Fatal("credential removal ignored")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["claim"] != 1 || calls["fail"] != 1 {
		t.Fatal("refused operations reached channel")
	}
}
func TestClaimBindingRefusals(t *testing.T) {
	cases := map[string]func(*Lease){"owner": func(l *Lease) { l.Job.Owner = "other" }, "pins": func(l *Lease) { l.Job.LockDigest = source.Hash([]byte("other")) }, "request": func(l *Lease) { l.Job.RequestDigest = source.Hash([]byte("other")) }, "map": func(l *Lease) { l.Map.Files = append(l.Map.Files, source.File{Path: "changed"}) }, "cancel": func(l *Lease) { l.Job.CancelRequested = true }, "deadline": func(l *Lease) { l.Deadline = time.Now().Add(-time.Second) }, "lease": func(l *Lease) { l.Token = "invalid" }, "tools": func(l *Lease) { l.Job.Input.Tools = []string{"shell"} }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			l := claim()
			change(&l)
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(wire(l)) }))
			if _, e := c.Claim(context.Background()); e == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
}
func TestHostileResponses(t *testing.T) {
	for name, body := range map[string]string{"duplicate": `{"state":"running","state":"running"}`, "alias": `{"State":"running"}`, "escaped": `{"state":"running","\u0073tate":"running"}`, "unknown": `{"state":"running","raw_output":"hidden"}`, "null": `{"state":null}`, "trailing": `{"state":"running"}{}`, "UTF8": "{\"state\":\"\xff\"}", "oversized": strings.Repeat(" ", 8193)} {
		t.Run(name, func(t *testing.T) {
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			if e := c.Guard(context.Background(), claim()); e == nil {
				t.Fatal("hostile response accepted")
			}
		})
	}
}
func TestEmptyRedirectAndErrorRedaction(t *testing.T) {
	for _, status := range []int{204, 302, 401, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == 302 {
					w.Header().Set("Location", "http://127.0.0.1:1/credential")
				}
				w.WriteHeader(status)
				if status != 204 {
					w.Write([]byte("sensitive server detail"))
				}
			}))
			_, e := c.Claim(context.Background())
			if status == 204 && !errors.Is(e, ErrEmpty) {
				t.Fatal("empty queue not distinguished")
			}
			if e == nil || strings.Contains(e.Error(), "sensitive") {
				t.Fatal("error redaction failed")
			}
		})
	}
}
func TestUnsafeCredential(t *testing.T) {
	c, path := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unsafe credential reached server") }))
	os.Chmod(path, 0644)
	if _, e := c.Claim(context.Background()); e == nil {
		t.Fatal("public credential accepted")
	}
	os.Remove(path)
	os.Symlink("missing", path)
	if _, e := c.Claim(context.Background()); e == nil {
		t.Fatal("symlink credential accepted")
	}
}

func TestUnsafeSocket(t *testing.T) {
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unsafe socket reached server") }))
	os.Chmod(c.socket, 0666)
	if _, e := New(c.socket, c.credential, c.owner, c.lock); e == nil {
		t.Fatal("public socket accepted")
	}
	if _, e := c.Claim(context.Background()); e == nil {
		t.Fatal("changed socket permissions ignored")
	}
}
func TestAcknowledgementsAndLocalGuardBinding(t *testing.T) {
	for _, body := range []string{`{"state":"completed"}`, `{"state":"tool_error","cleanup_required":false}`} {
		c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		if e := c.Guard(context.Background(), claim()); e == nil {
			t.Fatal("invalid guard acknowledgement accepted")
		}
		if e := c.Fail(context.Background(), claim(), "TOOL_UNAVAILABLE"); e == nil {
			t.Fatal("invalid failure acknowledgement accepted")
		}
	}
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("mutated claim reached guard") }))
	l := claim()
	l.Map.App = "another-application"
	if e := c.Guard(context.Background(), l); e == nil {
		t.Fatal("mutated source identity accepted")
	}
}
