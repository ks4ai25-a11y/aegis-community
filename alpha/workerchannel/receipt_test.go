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

func receiptFor(l Lease) scanevidence.Execution {
	s := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range s.Files {
		s.Bytes += f.Size
	}
	b, _ := json.Marshal(s)
	s.Digest = source.Hash(b)
	invocation, _ := scanevidence.BuildInvocation("bandit")
	return scanevidence.Execution{Schema: "1.0", Parser: scanevidence.ParserVersion, Tool: "bandit", Version: "1.9.4", Image: source.Hash([]byte("image")), LockDigest: l.Job.LockDigest, Snapshot: s, Started: l.Job.Created, Profile: "repo_offline-network-none-v1", Invocation: invocation, Exit: -1, Status: "tool_error", Cleanup: "unconfirmed", Result: scanevidence.Result{Status: "tool_error", Findings: []scanevidence.Finding{}, Diagnostics: []scanevidence.Diagnostic{}}, Limitations: []string{"private arbitrary presentation"}}
}
func TestReceiptUploadNormalizesAndBindsAcknowledgement(t *testing.T) {
	l := claim()
	time.Sleep(time.Millisecond)
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/scanner/receipt" {
			t.Error("wrong finite operation")
		}
		var wire struct {
			Schema, Job, Request, Token string
			Execution                   scanevidence.Execution
		}
		var raw map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			t.Error("invalid upload")
			return
		}
		json.Unmarshal(raw["schema_version"], &wire.Schema)
		json.Unmarshal(raw["job_id"], &wire.Job)
		json.Unmarshal(raw["request_digest"], &wire.Request)
		json.Unmarshal(raw["lease_token"], &wire.Token)
		json.Unmarshal(raw["execution"], &wire.Execution)
		if wire.Token != l.Token || wire.Job != l.Job.ID || wire.Request != l.Job.RequestDigest || wire.Execution.Limitations[0] == "private arbitrary presentation" {
			t.Error("upload binding or privacy failed")
		}
		doc, _ := json.Marshal(scanevidence.Document{Schema: "1.0", Owner: l.Job.Owner, Job: l.Job.ID, Request: l.Job.RequestDigest, Execution: wire.Execution})
		json.NewEncoder(w).Encode(ReceiptAcknowledgement{"1.0", l.Job.ID, l.Job.RequestDigest, "bandit", source.Hash(doc), "accepted", true})
	}))
	ack, e := c.SubmitReceipt(context.Background(), l, receiptFor(l))
	if e != nil || ack.State != "accepted" {
		t.Fatal("valid upload refused", e)
	}
	l.Deadline = time.Now().Add(-time.Second)
	if _, e = c.SubmitReceipt(context.Background(), l, receiptFor(l)); e != nil {
		t.Fatal("client prevented controller-authoritative receipt replay", e)
	}
	b, _ := json.Marshal(ack)
	if strings.Contains(string(b), l.Token) {
		t.Fatal("acknowledgement leaked lease capability")
	}
}
func TestReceiptAcknowledgementTamperingRefused(t *testing.T) {
	for _, kind := range []string{"digest", "job", "request", "tool", "state", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			l := claim()
			time.Sleep(time.Millisecond)
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				normalized, e := scanevidence.Normalize(receiptFor(l), scanevidence.Expected{Tools: l.Job.Input.Tools, App: l.Job.Input.App, Repository: l.Job.Input.Repository, LockDigest: l.Job.LockDigest, Tool: "bandit", Version: "1.9.4", Image: source.Hash([]byte("image")), Timeout: l.Job.Input.Duration, Map: l.Map, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now()})
				if e != nil {
					t.Error("fixture normalization failed")
					return
				}
				doc, _ := json.Marshal(scanevidence.Document{Schema: "1.0", Owner: l.Job.Owner, Job: l.Job.ID, Request: l.Job.RequestDigest, Execution: normalized})
				ack := ReceiptAcknowledgement{"1.0", l.Job.ID, l.Job.RequestDigest, "bandit", source.Hash(doc), "accepted", true}
				switch kind {
				case "digest":
					ack.Digest = source.Hash([]byte("wrong"))
				case "job":
					ack.Job = "other"
				case "request":
					ack.Request = "other"
				case "tool":
					ack.Tool = "syft"
				case "state":
					ack.State = "completed"
				case "cleanup":
					ack.Cleanup = false
				}
				json.NewEncoder(w).Encode(ack)
			}))
			if _, e := c.SubmitReceipt(context.Background(), l, receiptFor(l)); e == nil {
				t.Fatal("tampered acknowledgement accepted")
			}
		})
	}
}
