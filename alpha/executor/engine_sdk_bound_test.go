// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package executor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// slowEngine is a complete synthetic lifecycle whose replies to the named
// operations ("create", "start", "remove", "list") are held for a delay before
// any header is written. It counts every request so a retry would be visible.
type slowEngine struct {
	mu     sync.Mutex
	counts map[string]int
	late   chan string
}

func (s *slowEngine) count(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[op]
}
func newSlowEngine(t *testing.T, id string, delays map[string]time.Duration) (*slowEngine, string, string, string) {
	t.Helper()
	s := &slowEngine{counts: map[string]int{}, late: make(chan string, 8)}
	started, stop := make(chan struct{}), make(chan struct{})
	var startOnce, stopOnce sync.Once
	t.Cleanup(func() { stopOnce.Do(func() { close(stop) }) })
	hold := func(op string) bool {
		s.mu.Lock()
		s.counts[op]++
		s.mu.Unlock()
		select {
		case <-time.After(delays[op]):
			return true
		case <-stop:
			return false
		}
	}
	endpoint, path, engine := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		prefix := "/v" + engineAPIVersion + "/containers/"
		switch r.URL.Path {
		case prefix + "create":
			if !hold("create") {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			io.WriteString(w, `{"Id":"`+id+`","Warnings":[]}`)
			if delays["create"] > 0 {
				s.late <- "create"
			}
		case prefix + id + "/attach":
			conn, buf, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer conn.Close()
			buf.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			buf.Flush()
			select {
			case <-started:
			case <-stop:
				return
			}
			buf.Write(sdkFrame(1, "bounded stdout"))
			buf.Flush()
		case prefix + id + "/wait":
			if r.URL.Query().Get("condition") == "removed" {
				io.WriteString(w, `{"StatusCode":0,"Error":null}`)
				return
			}
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			select {
			case <-started:
			case <-r.Context().Done():
				return
			case <-stop:
				return
			}
			io.WriteString(w, `{"StatusCode":0,"Error":null}`)
		case prefix + id + "/start":
			if !hold("start") {
				return
			}
			w.WriteHeader(204)
			startOnce.Do(func() { close(started) })
		case prefix + id:
			if !hold("remove") {
				return
			}
			w.WriteHeader(204)
			if delays["remove"] > 0 {
				s.late <- "remove"
			}
		case prefix + "json":
			if !hold("list") {
				return
			}
			io.WriteString(w, "[]")
		default:
			t.Error("unexpected engine request", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})
	return s, endpoint, path, engine
}

// The hosted daemon took up to 5.5 s to answer create under writeback
// pressure. With the production bounds, a reply that arrives after the 5 s
// read bound is now awaited and confirmed, once, for every tracked mutation.
func TestSDKSlowMutationRepliesPastReadBoundAreConfirmed(t *testing.T) {
	if engineReadBound != 5*time.Second || engineMutationBound <= 5500*time.Millisecond {
		t.Fatal("production bounds changed", engineReadBound, engineMutationBound)
	}
	slow := 5500 * time.Millisecond
	id := strings.Repeat("f", 64)
	name := "aegis-scan-" + strings.Repeat("f", 32)
	engine, endpoint, path, digest := newSlowEngine(t, id, map[string]time.Duration{"create": slow, "start": slow, "remove": slow})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out := (Config{EngineJournalRoot: path}).runEngineSDK(ctx, endpoint, digest, name, client.ContainerCreateOptions{Name: name, Image: "fixed-test-image"}, io.Discard, io.Discard, cancel)
	state := journalState(t, path, digest)
	if out.err != nil || !out.cleanup || out.exit != 0 || state.Unresolved != 0 || state.Unfinished != 0 {
		t.Fatal("slow mutation was abandoned", out, state)
	}
	for _, op := range []string{"create", "start", "remove", "list"} {
		if engine.count(op) != 1 {
			t.Fatal("mutation retried or skipped", op, engine.count(op))
		}
	}
}

// Scaled bounds keep this fast. A mutation reply beyond the mutation bound is
// still abandoned: the obligation stays unresolved, a late complete reply does
// not settle it, and the namespace admits no further writes. Reads keep the
// shorter read bound.
func TestSDKMutationReplyBeyondBoundStaysUnresolved(t *testing.T) {
	read, mutation := engineReadBound, engineMutationBound
	engineReadBound, engineMutationBound = 200*time.Millisecond, time.Second
	t.Cleanup(func() { engineReadBound, engineMutationBound = read, mutation })
	beyond := 1500 * time.Millisecond
	id := strings.Repeat("9", 64)
	name := "aegis-scan-" + strings.Repeat("9", 32)
	next := "aegis-scan-" + strings.Repeat("8", 32)
	run := func(endpoint, path, digest, name string) sdkOutcome {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return (Config{EngineJournalRoot: path}).runEngineSDK(ctx, endpoint, digest, name, client.ContainerCreateOptions{Name: name, Image: "fixed-test-image"}, io.Discard, io.Discard, cancel)
	}
	for _, tc := range []struct {
		op     string
		delays map[string]time.Duration
	}{
		{"create", map[string]time.Duration{"create": beyond}},
		{"remove", map[string]time.Duration{"remove": beyond}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			engine, endpoint, path, digest := newSlowEngine(t, id, tc.delays)
			out := run(endpoint, path, digest, name)
			before := journalState(t, path, digest)
			if out.err == nil || out.cleanup || before.Unresolved != 1 || before.Unfinished != 1 || before.CleanupAuthorized {
				t.Fatal("reply beyond the mutation bound was settled", out, before)
			}
			select {
			case op := <-engine.late:
				if op != tc.op {
					t.Fatal("unexpected late reply", op)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("late reply not sent")
			}
			if after := journalState(t, path, digest); after != before {
				t.Fatal("late reply rewrote durable uncertainty", after)
			}
			requests := engine.count(tc.op)
			if out := run(endpoint, path, digest, next); out.err == nil || out.cleanup || requests != 1 || engine.count("create") != 1 {
				t.Fatal("mutation retried or held namespace admitted more writes", out, requests)
			}
		})
	}
	t.Run("read", func(t *testing.T) {
		// 500 ms is within the mutation bound but beyond the read bound: the
		// remove is confirmed, the absence read is not, so cleanup stays
		// unconfirmed and the executor keeps the dispatch held.
		engine, endpoint, path, digest := newSlowEngine(t, id, map[string]time.Duration{"create": 500 * time.Millisecond, "remove": 500 * time.Millisecond, "list": 500 * time.Millisecond})
		out := run(endpoint, path, digest, name)
		state := journalState(t, path, digest)
		if out.err == nil || out.cleanup || state.Unresolved != 0 || engine.count("remove") != 1 || engine.count("list") != 1 {
			t.Fatal("read used the mutation bound", out, state)
		}
	})
}
