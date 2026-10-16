//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package executor

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/source"
	"context"
	"github.com/moby/moby/client"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBoundSDKRechecksExistingJournalUnderLockBeforeAnyMutation(t *testing.T) {
	for _, kind := range []string{"approved", "namespace", "root", "missing", "replaced", "busy", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			endpoint, path, engine := sdkFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(501) })
			j, e := enginejournal.Open(path, engine)
			if e != nil {
				t.Fatal(e)
			}
			original := j.Observe()
			j.Close()
			cfg := Config{EngineJournalRoot: path, ExpectedJournalNamespace: original.Namespace, ExpectedJournalRootDigest: source.Hash([]byte("aegis-scanner-engine-journal-root-v1\n" + path + "\n" + strconv.Itoa(os.Geteuid())))}
			switch kind {
			case "namespace":
				cfg.ExpectedJournalNamespace = source.Hash([]byte("other"))
			case "root":
				cfg.ExpectedJournalRootDigest = source.Hash([]byte("other"))
			case "missing":
				if e = os.RemoveAll(path); e != nil {
					t.Fatal(e)
				}
			case "replaced":
				if e = os.Rename(path, path+"-retained"); e != nil {
					t.Fatal(e)
				}
				replacement, e := enginejournal.Open(path, engine)
				if e != nil {
					t.Fatal(e)
				}
				if replacement.Observe().Namespace == original.Namespace {
					t.Fatal("namespace reused")
				}
				replacement.Close()
			case "busy":
				held, e := enginejournal.OpenExisting(path, engine)
				if e != nil {
					t.Fatal(e)
				}
				defer held.Close()
			case "incomplete":
				cfg.ExpectedJournalNamespace = ""
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			name := "aegis-scan-" + strings.Repeat("a", 32)
			out := cfg.runEngineSDK(ctx, endpoint, engine, name, client.ContainerCreateOptions{Name: name, Image: "fixed-fixture"}, io.Discard, io.Discard, cancel)
			if out.err == nil || out.cleanup {
				t.Fatal("failed create/namespace became cleanup", out)
			}
			expected := int32(0)
			if kind == "approved" {
				expected = 1
			}
			if calls.Load() != expected {
				t.Fatal("unapproved engine mutation", kind, calls.Load())
			}
			if kind == "missing" {
				if _, e = os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("missing bound namespace recreated")
				}
			}
		})
	}
}
