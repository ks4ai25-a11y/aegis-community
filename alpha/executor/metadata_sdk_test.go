//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package executor

import (
	"aegis.local/source"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func metadataTool() Tool {
	return Tool{ID: "bandit", Version: "fixture", Image: "example.invalid/bandit@sha256:" + strings.Repeat("a", 64)}
}
func validMetadataImage(tool Tool) string {
	b, _ := json.Marshal(map[string]any{"Id": "sha256:" + strings.Repeat("b", 64), "RepoDigests": []string{tool.Image}, "Os": "linux", "Architecture": "arm64"})
	return string(b)
}

const validMetadataInfo = `{"OSType":"linux","Architecture":"aarch64","ID":"fixture-engine"}`

func TestSDKPreflightIsBoundedReadOnlyAndIndependentOfCLI(t *testing.T) {
	tool := metadataTool()
	var requests atomic.Int32
	endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" {
			t.Error("non-read metadata method")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.55/info" {
			w.Write([]byte(validMetadataInfo))
		} else if r.URL.Path == "/v1.55/images/"+tool.Image+"/json" {
			w.Write([]byte(validMetadataImage(tool)))
		} else {
			t.Error("unexpected metadata resource")
			w.WriteHeader(404)
		}
	})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("DOCKER_API_VERSION", "0.1")
	out, e := preflightSDK(context.Background(), endpoint, tool, source.Hash([]byte("lock")))
	if e != nil || out.Architecture != "arm64" || out.Engine != source.Hash([]byte(endpoint+"\nfixture-engine")) || out.Image != strings.Split(tool.Image, "@")[1] || out.Config != "sha256:"+strings.Repeat("b", 64) || out.Writes || out.Release || requests.Load() != 2 {
		t.Fatal(out, e, requests.Load())
	}

}
func TestSDKMetadataRejectsIncompleteAmbiguousAndUnsupportedResponses(t *testing.T) {
	tool := metadataTool()
	cases := map[string]struct {
		info, image string
		status      int
	}{
		"empty-info": {"", validMetadataImage(tool), 200}, "trailing-info": {validMetadataInfo + ` {}`, validMetadataImage(tool), 200}, "duplicate-info": {`{"OSType":"linux","Architecture":"arm64","ID":"one","ID":"two"}`, validMetadataImage(tool), 200}, "aliased-info": {`{"OSType":"linux","Architecture":"arm64","ID":"one","id":"two"}`, validMetadataImage(tool), 200}, "oversized-info": {`{"OSType":"linux","Architecture":"arm64","ID":"engine","padding":"` + strings.Repeat("x", 65536) + `"}`, validMetadataImage(tool), 200}, "unknown-field": {`{"OSType":"linux","Architecture":"arm64","ID":"engine","new_authority":true}`, validMetadataImage(tool), 200}, "windows": {`{"OSType":"windows","Architecture":"arm64","ID":"engine"}`, validMetadataImage(tool), 200}, "unknown-architecture": {`{"OSType":"linux","Architecture":"riscv64","ID":"engine"}`, validMetadataImage(tool), 200}, "missing-id": {`{"OSType":"linux","Architecture":"arm64"}`, validMetadataImage(tool), 200}, "id-controls": {`{"OSType":"linux","Architecture":"arm64","ID":"engine\nunsafe"}`, validMetadataImage(tool), 200}, "status-error": {validMetadataInfo, validMetadataImage(tool), 500},
		"bad-image": {validMetadataInfo, `{`, 200}, "image-trailing": {validMetadataInfo, validMetadataImage(tool) + ` {}`, 200}, "wrong-pin": {validMetadataInfo, `{"Id":"sha256:` + strings.Repeat("b", 64) + `","RepoDigests":["example.invalid/bandit@sha256:` + strings.Repeat("c", 64) + `"],"Os":"linux","Architecture":"arm64"}`, 200}, "wrong-image-arch": {validMetadataInfo, strings.Replace(validMetadataImage(tool), "arm64", "amd64", 1), 200}, "wrong-image-os": {validMetadataInfo, strings.Replace(validMetadataImage(tool), "linux", "windows", 1), 200}, "null-image": {validMetadataInfo, `null`, 200}, "oversized-image": {validMetadataInfo, strings.Repeat(" ", 65537), 200},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var mutations atomic.Int32
			endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					mutations.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				if strings.HasSuffix(r.URL.Path, "/info") {
					w.Write([]byte(c.info))
				} else {
					w.Write([]byte(c.image))
				}
			})
			if out, e := preflightSDK(context.Background(), endpoint, tool, source.Hash([]byte("lock"))); e == nil || out.Schema != "" || mutations.Load() != 0 {
				t.Fatal("unsafe metadata accepted", out, e)
			}
		})
	}
}
func TestSDKMetadataRejectsRedirectAndCancelledStalledResponse(t *testing.T) {
	tool := metadataTool()
	var external atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { external.Add(1) }))
	defer trap.Close()
	endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Location", trap.URL); w.WriteHeader(302) })
	if _, e := preflightSDK(context.Background(), endpoint, tool, source.Hash([]byte("lock"))); e == nil || external.Load() != 0 {
		t.Fatal("redirect followed")
	}
	stalled, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(200)
		w.Write([]byte(validMetadataInfo))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, e := preflightSDK(ctx, stalled, tool, source.Hash([]byte("lock"))); e == nil || time.Since(started) > 2*time.Second {
		t.Fatal("partial response became a completed preflight")
	}
}
func TestMetadataClientWhitelistExcludesMutationAndExtraQueries(t *testing.T) {
	active := &responseCapture{operation: "info"}
	hook, _ := metadataHooks(metadataTool().Image, &active)
	for _, target := range []struct{ method, path string }{{"POST", "/v1.55/containers/create"}, {"GET", "/v1.55/info?extra=1"}, {"GET", "/v1.55/info?"}, {"GET", "/v1.55/containers/json"}, {"GET", "/v1.56/info"}, {"GET", "/v1.55/images/other/json"}} {
		r := httptest.NewRequest(target.method, "http://docker"+target.path, nil)
		r = r.WithContext(context.WithValue(r.Context(), captureKey{}, active))
		if hook(r) == nil {
			t.Fatal("metadata capability escaped", target)
		}
	}
}

func TestExplicitSDKPreflightNeverInvokesMissingDockerCLI(t *testing.T) {
	tool := metadataTool()
	var calls atomic.Int32
	endpoint, _, _ := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/info") {
			w.Write([]byte(validMetadataInfo))
		} else {
			w.Write([]byte(validMetadataImage(tool)))
		}
	})
	lock := filepath.Join(t.TempDir(), "lock.json")
	data, _ := json.Marshal(map[string]any{"schema_version": "1.0", "tools": []Tool{tool}})
	if e := os.WriteFile(lock, data, 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("DOCKER_HOST", endpoint)
	t.Setenv("DOCKER_CONTEXT", "")
	cfg := Config{Docker: "/no/docker/executable", LockPath: lock}
	if _, e := cfg.Preflight(context.Background(), "bandit"); e != nil || calls.Load() != 2 {
		t.Fatal("explicit SDK endpoint required CLI", e)
	}
	for _, setting := range []struct{ host, context, tool string }{{endpoint, "unexpected-context", "bandit"}, {"tcp://127.0.0.1:2375", "", "bandit"}, {"", "", "bandit"}, {endpoint, "", "unsupported"}} {
		before := calls.Load()
		t.Setenv("DOCKER_HOST", setting.host)
		t.Setenv("DOCKER_CONTEXT", setting.context)
		if _, e := cfg.Preflight(context.Background(), setting.tool); e == nil || calls.Load() != before {
			t.Fatal("invalid selection reached engine", e)
		}
	}
}
