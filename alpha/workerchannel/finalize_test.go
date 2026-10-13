//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func suiteFixture(l Lease) (SuiteResult, []ReceiptAcknowledgement) {
	digest := source.Hash([]byte("accepted receipt"))
	refs := []ReceiptAcknowledgement{{Schema: "1.0", Job: l.Job.ID, Request: l.Job.RequestDigest, Tool: "bandit", Digest: digest, State: "accepted", Cleanup: true}}
	m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range m.Files {
		m.Bytes += f.Size
	}
	b, _ := json.Marshal(m)
	d := scanevidence.Suite{Schema: "1.0", Owner: l.Job.Owner, Job: l.Job.ID, Request: l.Job.RequestDigest, App: l.Job.Input.App, Repository: l.Job.Input.Repository, Map: l.Map.Digest, Lock: l.Job.LockDigest, Snapshot: source.Hash(b), Status: "completed", Tools: []scanevidence.SuiteTool{{Tool: "bandit", Receipt: digest, Status: "completed"}}, Tier: "T0", CleanupRequired: true, Created: time.Now().UTC().Format(time.RFC3339Nano)}
	b, _ = json.Marshal(d)
	return SuiteResult{Digest: source.Hash(b), Document: d}, refs
}

func TestFinishBindsExactAcceptedReceiptsAndExpiredReplay(t *testing.T) {
	l := claim()
	out, refs := suiteFixture(l)
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/internal/v1/scanner/finish" || !strings.Contains(string(b), l.Token) || strings.Contains(string(b), "cleanup") || strings.Contains(string(b), "state") {
			t.Error("finish supplied state/cleanup or lost private capability")
		}
		json.NewEncoder(w).Encode(out)
	}))
	got, e := c.Finish(context.Background(), l, refs)
	if e != nil || got.Digest != out.Digest {
		t.Fatal(got, e)
	}
	l.Deadline = time.Now().Add(-time.Second)
	out.Document.Created = l.Deadline.Add(-time.Second).Format(time.RFC3339Nano)
	l.Job.Created = l.Deadline.Add(-time.Minute).Format(time.RFC3339Nano)
	// Rebind the immutable job request after fixture timestamp changes is not
	// necessary: created_at is not part of the original request digest.
	b, _ := json.Marshal(out.Document)
	out.Digest = source.Hash(b)
	if _, e = c.Finish(context.Background(), l, refs); e != nil {
		t.Fatal("expired committed result replay refused locally", e)
	}
}

func TestFinishRejectsIndependentlyAlteredAcknowledgements(t *testing.T) {
	for _, kind := range []string{"owner", "job", "request", "app", "repository", "map", "lock", "snapshot", "tool", "receipt", "status", "claims", "flags", "tier", "cleanup", "timestamp", "hash"} {
		t.Run(kind, func(t *testing.T) {
			l := claim()
			out, refs := suiteFixture(l)
			switch kind {
			case "owner":
				out.Document.Owner = "owner-b"
			case "job":
				out.Document.Job = "another-job"
			case "request":
				out.Document.Request = source.Hash([]byte("wrong"))
			case "app":
				out.Document.App = "wrong"
			case "repository":
				out.Document.Repository = "wrong"
			case "map":
				out.Document.Map = source.Hash([]byte("wrong"))
			case "lock":
				out.Document.Lock = source.Hash([]byte("wrong"))
			case "snapshot":
				out.Document.Snapshot = source.Hash([]byte("wrong"))
			case "tool":
				out.Document.Tools[0].Tool = "syft"
			case "receipt":
				out.Document.Tools[0].Receipt = source.Hash([]byte("wrong"))
			case "status":
				out.Document.Status = "secure"
			case "claims":
				out.Document.FindingClaims = 1
			case "flags":
				out.Document.Stale = true
			case "tier":
				out.Document.Tier = "T3"
			case "cleanup":
				out.Document.CleanupRequired = false
			case "timestamp":
				out.Document.Created = l.Deadline.Add(time.Second).Format(time.RFC3339Nano)
			}
			b, _ := json.Marshal(out.Document)
			out.Digest = source.Hash(b)
			if kind == "hash" {
				out.Digest = source.Hash([]byte("wrong"))
			}
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(out) }))
			if _, e := c.Finish(context.Background(), l, refs); e == nil {
				t.Fatal("altered finish acknowledgement accepted")
			}
		})
	}
}
