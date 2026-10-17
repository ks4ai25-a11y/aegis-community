// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package executor

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/source"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func sdkFixture(t *testing.T, handler http.HandlerFunc) (string, string, string) {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("non-root operator")
	}
	short, e := os.MkdirTemp("", "aegis-sdk-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	parent, e := filepath.EvalSymlinks(short)
	if e != nil {
		t.Fatal(e)
	}
	// Unix socket names have a platform length bound; TempDir already reserves a
	// random directory, so the socket basename can remain short.
	socket := filepath.Join(parent, "s")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close(); listener.Close() })
	return "unix://" + socket, filepath.Join(parent, "journal"), source.Hash([]byte("owned synthetic engine"))
}
func journalState(t *testing.T, path, engine string) enginejournal.Observation {
	t.Helper()
	j, e := enginejournal.Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	return j.Observe()
}
func TestSDKUnconfirmedCreateSurvivesCompleteLaterDaemonResponse(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	endpoint, path, engine := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		close(entered)
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"Id": strings.Repeat("a", 64), "Warnings": []string{}})
		close(finished)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan sdkOutcome, 1)
	cfg := Config{EngineJournalRoot: path}
	name := "aegis-scan-" + strings.Repeat("a", 32)
	go func() {
		done <- cfg.runEngineSDK(ctx, endpoint, engine, name, client.ContainerCreateOptions{Name: name, Image: "fixed-test-image"}, io.Discard, io.Discard, cancel)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("create not sent")
	}
	cancel()
	select {
	case out := <-done:
		if out.cleanup || out.err == nil {
			t.Fatal("cancel became confirmed", out)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not join")
	}
	before := journalState(t, path, engine)
	if before.Unresolved != 1 || before.Unfinished != 1 || before.CleanupAuthorized {
		t.Fatal(before)
	}
	close(release)
	<-finished
	after := journalState(t, path, engine)
	if after != before {
		t.Fatal("late response rewrote durable uncertainty")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := cfg.runEngineSDK(ctx, endpoint, engine, "aegis-scan-"+strings.Repeat("b", 32), client.ContainerCreateOptions{Name: "aegis-scan-" + strings.Repeat("b", 32), Image: "fixed-test-image"}, io.Discard, io.Discard, cancel)
	if out.cleanup || out.err == nil || requests.Load() != 1 {
		t.Fatal("pending namespace admitted more writes")
	}
}
func TestSDKInvalidCreateResponsesRemainUnresolved(t *testing.T) {
	for _, kind := range []string{"truncated", "oversized", "bad_id", "unexpected_status", "trailing_json", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			endpoint, path, engine := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "truncated":
					w.Header().Set("Content-Length", "1000")
					w.WriteHeader(201)
					io.WriteString(w, `{"Id":"`)
				case "oversized":
					w.WriteHeader(201)
					io.WriteString(w, `{"Id":"`+strings.Repeat("a", 64)+`","Warnings":[],"padding":"`+strings.Repeat("x", 65536)+`"}`)
				case "bad_id":
					w.WriteHeader(201)
					io.WriteString(w, `{"Id":"short","Warnings":[]}`)
				case "unexpected_status":
					w.WriteHeader(200)
					io.WriteString(w, `{"Id":"`+strings.Repeat("a", 64)+`","Warnings":[]}`)
				case "trailing_json":
					w.WriteHeader(201)
					io.WriteString(w, `{"Id":"`+strings.Repeat("a", 64)+`","Warnings":[]} {}`)
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1/forbidden")
					w.WriteHeader(307)
				}
			})
			name := "aegis-scan-" + strings.Repeat("c", 32)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out := (Config{EngineJournalRoot: path}).runEngineSDK(ctx, endpoint, engine, "aegis-scan-"+strings.Repeat("c", 32), client.ContainerCreateOptions{Name: name, Image: "fixed-test-image"}, io.Discard, io.Discard, cancel)
			if out.err == nil || out.cleanup || requests.Load() != 1 {
				t.Fatal("invalid response accepted", out)
			}
			state := journalState(t, path, engine)
			if state.Unresolved != 1 || state.Unfinished != 1 {
				t.Fatal(state)
			}
		})
	}
}
func sdkFrame(stream byte, text string) []byte {
	b := make([]byte, 8+len(text))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(text)))
	copy(b[8:], text)
	return b
}
func TestSDKLifecycleRegistersWaitBeforeStartAndJoinsCancellation(t *testing.T) {
	for _, mode := range []string{"complete", "removed_404", "remove_refused", "remove_truncated", "wait_refused", "unknown_start", "stream_cancel"} {
		t.Run(mode, func(t *testing.T) {
			id := strings.Repeat("d", 64)
			name := "aegis-scan-" + strings.Repeat("d", 32)
			registered, started, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(stop) })
			var startCount, removeCount atomic.Int32
			endpoint, path, engine := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				prefix := "/v" + engineAPIVersion + "/containers/"
				switch r.URL.Path {
				case prefix + "create":
					w.WriteHeader(201)
					io.WriteString(w, `{"Id":"`+id+`","Warnings":[]}`)
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
					if mode == "stream_cancel" {
						buf.Write([]byte{9, 0, 0, 0, 0, 0, 0, 0})
					} else {
						buf.Write(sdkFrame(1, "bounded stdout"))
						buf.Write(sdkFrame(2, "bounded stderr"))
					}
					buf.Flush()
				case prefix + id + "/wait":
					if r.URL.Query().Get("condition") == "removed" {
						io.WriteString(w, `{"StatusCode":0,"Error":null}`)
						return
					}
					if mode == "wait_refused" {
						w.WriteHeader(500)
						io.WriteString(w, `{"message":"synthetic refusal"}`)
						return
					}
					if r.URL.Query().Get("condition") != "next-exit" {
						t.Error("wait condition")
					}
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					close(registered)
					select {
					case <-started:
					case <-r.Context().Done():
						return
					case <-stop:
						return
					}
					if mode == "stream_cancel" || mode == "unknown_start" {
						select {
						case <-r.Context().Done():
						case <-stop:
						}
						return
					}
					io.WriteString(w, `{"StatusCode":1,"Error":null}`)
				case prefix + id + "/start":
					select {
					case <-registered:
					default:
						t.Error("started before wait acknowledgement")
					}
					startCount.Add(1)
					close(started)
					if mode == "unknown_start" {
						select {
						case <-r.Context().Done():
						case <-stop:
						}
						return
					}
					w.WriteHeader(204)
				case prefix + id:
					removeCount.Add(1)
					if mode == "remove_refused" {
						w.WriteHeader(409)
						io.WriteString(w, `{"message":"removal in progress"}`)
						return
					}
					if mode == "remove_truncated" {
						w.Header().Set("Content-Length", "1000")
						w.WriteHeader(404)
						io.WriteString(w, `{"message":`)
						return
					}
					if mode == "removed_404" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(404)
						io.WriteString(w, `{"message":"No such container"}`)
						return
					}
					w.WriteHeader(204)
				case prefix + "json":
					io.WriteString(w, "[]")
				default:
					t.Error("unexpected engine request", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			var stdout, stderr bytes.Buffer
			out := (Config{EngineJournalRoot: path}).runEngineSDK(ctx, endpoint, engine, name, client.ContainerCreateOptions{Name: name, Image: "fixed-test-image"}, &stdout, &stderr, cancel)
			once.Do(func() { close(stop) })
			state := journalState(t, path, engine)
			switch mode {
			case "complete", "removed_404":
				if out.err != nil || !out.cleanup || out.exit != 1 || stdout.String() != "bounded stdout" || stderr.String() != "bounded stderr" || state.Unresolved != 0 || state.Unfinished != 0 {
					t.Fatal("lifecycle", out, state)
				}
			case "wait_refused":
				if out.err == nil || !out.cleanup || startCount.Load() != 0 || removeCount.Load() != 1 || state.Unresolved != 0 {
					t.Fatal("failed wait started scanner", out, state)
				}
			case "unknown_start":
				if out.err == nil || out.cleanup || removeCount.Load() != 0 || state.Unresolved != 1 {
					t.Fatal("unknown start erased", out, state)
				}
			case "remove_refused", "remove_truncated":
				if out.err == nil || out.cleanup || state.Unresolved != 1 || state.Unfinished != 1 || removeCount.Load() != 1 {
					t.Fatal("unconfirmed removal erased", out, state)
				}
			case "stream_cancel":
				// Malformed output can cancel concurrently with the start response.
				// Only a settled start permits tracked removal; an unanswered start
				// must stay pending rather than invent completion.
				if out.err == nil || out.cleanup && (state.Unresolved != 0 || state.Unfinished != 0) || !out.cleanup && (state.Unresolved != 1 || state.Unfinished != 1) {
					t.Fatal("invalid stream accepted", out, state)
				}
			}
		})
	}
}
func TestSDKMultiplexedStreamsRejectMalformedAndOverflow(t *testing.T) {
	for _, data := range [][]byte{{1}, {0, 0, 0, 0, 0, 0, 0, 0}, {1, 1, 0, 0, 0, 0, 0, 0}, {1, 0, 0, 0, 0, 128, 0, 1}, sdkFrame(1, "secret")[:10]} {
		if copyEngineStreams(bytes.NewReader(data), io.Discard, io.Discard) == nil {
			t.Fatal("malformed frame accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &cappedOutput{limit: 2, cancel: cancel}
	if copyEngineStreams(bytes.NewReader(sdkFrame(1, "large")), out, io.Discard) == nil || ctx.Err() == nil {
		t.Fatal("overflow did not cancel")
	}
}
func TestSDKHooksRejectOtherResourcesAndAmbientConfiguration(t *testing.T) {
	name := "aegis-scan-" + strings.Repeat("e", 32)
	id := strings.Repeat("e", 64)
	hook, _ := engineHooks(name, &id)
	for _, path := range []string{"/_ping", "/v1.55/images/create", "/v1.55/containers/other/start", "/v1.55/containers/json?all=1"} {
		r, _ := http.NewRequest("POST", "http://docker"+path, nil)
		if hook(r) == nil {
			t.Fatal("unscoped operation accepted")
		}
	}
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "1.1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	sdk, e := newEngineSDK(endpoint, name, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer sdk.Close()
	capture := &responseCapture{operation: "start", id: id}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), captureKey{}, capture), time.Second)
	defer cancel()
	if _, e = sdk.ContainerStart(ctx, id, client.ContainerStartOptions{}); e != nil || !observed(capture, 204) {
		t.Fatal("explicit socket/API not honored", e)
	}
}

func TestSDKCompleteCreateResponseIsCaptured(t *testing.T) {
	id := strings.Repeat("f", 64)
	name := "aegis-scan-" + strings.Repeat("f", 32)
	endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		io.WriteString(w, `{"Id":"`+id+`","Warnings":[]}`)
	})
	known := ""
	sdk, e := newEngineSDK(endpoint, name, &known)
	if e != nil {
		t.Fatal(e)
	}
	defer sdk.Close()
	capture := &responseCapture{operation: "create", name: name}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), captureKey{}, capture), time.Second)
	defer cancel()
	got, e := sdk.ContainerCreate(ctx, client.ContainerCreateOptions{Name: name, Image: "fixed-test-image"})
	if e != nil || !observedCreate(capture, got.ID) {
		t.Fatalf("capture: err=%v id=%s status=%d complete=%t failed=%t payload=%q", e, got.ID, capture.status, capture.complete, capture.failed, capture.payload)
	}
}
