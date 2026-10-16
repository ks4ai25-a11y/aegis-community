//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
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

func TestJournalBindingClientRejectsChangedBaseOwnerDigestAndAmbiguousWire(t *testing.T) {
	for _, kind := range []string{"valid", "owner", "base", "digest", "future", "before-base", "unknown", "duplicate", "oversized", "noncanonical", "server-error"} {
		t.Run(kind, func(t *testing.T) {
			base := bindingFixture()
			d := scanevidence.JournalBinding{Schema: "1.0", Owner: "owner-a", EngineBinding: base.Digest, Root: source.Hash([]byte("root")), Namespace: source.Hash([]byte("namespace")), Created: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
			switch kind {
			case "owner":
				d.Owner = "owner-b"
			case "base":
				d.EngineBinding = source.Hash([]byte("other"))
			case "future":
				d.Created = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "before-base":
				d.Created = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			}
			b, _ := json.Marshal(d)
			r := scanevidence.JournalBindingRecord{Digest: source.Hash(b), Document: d}
			if kind == "digest" {
				r.Digest = source.Hash([]byte("other"))
			}
			raw, _ := json.Marshal(r)
			switch kind {
			case "unknown":
				raw = []byte(strings.Replace(string(raw), `{"journal_binding_digest":`, `{"extra":true,"journal_binding_digest":`, 1))
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `{"journal_binding_digest":`, `{"journal_binding_digest":"bad","journal_binding_digest":`, 1))
			case "oversized":
				raw = []byte(strings.Repeat(" ", 2049))
			case "noncanonical":
				raw = []byte(strings.Replace(string(raw), `{"journal_binding_digest":`, `{"journal_binding_digest": `, 1))
			}
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Method != "POST" || request.URL.Path != "/internal/v1/scanner/engine-journal-binding" {
					t.Error("wrong channel operation")
				}
				if kind == "server-error" {
					w.WriteHeader(409)
				}
				w.Write(raw)
			}))
			out, e := c.JournalBinding(context.Background(), base)
			if kind == "valid" {
				if e != nil || out != r {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("unsafe binding accepted", kind)
			}
		})
	}
}
