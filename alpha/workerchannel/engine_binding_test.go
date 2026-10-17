//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func bindingFixture() scanevidence.EngineBindingRecord {
	d := scanevidence.EngineBinding{Schema: "1.0", Owner: "owner-a", Engine: source.Hash([]byte("engine")), Registry: source.Hash([]byte("registry")), Created: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
	b, _ := json.Marshal(d)
	return scanevidence.EngineBindingRecord{Digest: source.Hash(b), Document: d}
}
func TestPrivateEngineBindingClientValidatesCanonicalOwnerScopeAndDigest(t *testing.T) {
	for _, kind := range []string{"valid", "owner", "hash", "future", "unknown", "duplicate", "oversized", "noncanonical", "server-error"} {
		t.Run(kind, func(t *testing.T) {
			bound := bindingFixture()
			if kind == "owner" {
				bound.Document.Owner = "owner-b"
			}
			if kind == "future" {
				bound.Document.Created = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			}
			b, _ := json.Marshal(bound.Document)
			bound.Digest = source.Hash(b)
			if kind == "hash" {
				bound.Digest = source.Hash([]byte("wrong"))
			}
			raw, _ := json.Marshal(bound)
			switch kind {
			case "unknown":
				raw = []byte(strings.Replace(string(raw), `{"binding_digest":`, `{"extra":true,"binding_digest":`, 1))
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `{"binding_digest":`, `{"binding_digest":"wrong","binding_digest":`, 1))
			case "oversized":
				raw = []byte(strings.Repeat(" ", 2049))
			case "noncanonical":
				raw = []byte(strings.Replace(string(raw), `{"binding_digest":`, `{"binding_digest": `, 1))
			}
			calls := 0
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/internal/v1/scanner/engine-binding" || r.Method != "POST" {
					t.Error("wrong private operation")
				}
				if kind == "server-error" {
					w.WriteHeader(409)
				}
				w.Write(raw)
			}))
			out, e := c.EngineBinding(context.Background())
			if calls != 1 {
				t.Fatal(calls)
			}
			if kind == "valid" {
				if e != nil || out != bound {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("unsafe binding accepted", kind)
			}
		})
	}
}
