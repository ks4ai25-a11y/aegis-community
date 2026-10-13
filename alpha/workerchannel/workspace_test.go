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
	"sync/atomic"
	"testing"
	"time"
)

func clientWorkspaceFixture(l Lease) (scanevidence.WorkspaceRecord, scanevidence.WorkspacePlan) {
	m := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range m.Files {
		m.Bytes += f.Size
	}
	b, _ := json.Marshal(m)
	p := scanevidence.WorkspacePlan{Tool: "bandit", Workspace: "run-" + strings.Repeat("a", 32), Registry: source.Hash([]byte("registry")), Snapshot: source.Hash(b)}
	d := scanevidence.Workspace{Schema: "1.0", Owner: l.Job.Owner, Job: l.Job.ID, Request: l.Job.RequestDigest, App: l.Job.Input.App, Repository: l.Job.Input.Repository, Map: l.Map.Digest, Lock: l.Job.LockDigest, Plan: p, Created: time.Now().UTC().Format(time.RFC3339Nano), Deadline: l.Deadline.Format(time.RFC3339Nano)}
	b, _ = json.Marshal(d)
	return scanevidence.WorkspaceRecord{Digest: source.Hash(b), Document: d}, p
}

func TestWorkspaceClientBindsAcknowledgementAndRefusesExpiredRegistration(t *testing.T) {
	l := claim()
	record, p := clientWorkspaceFixture(l)
	var calls atomic.Int32
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/internal/v1/scanner/workspace" {
			t.Error("unexpected workspace path")
		}
		json.NewEncoder(w).Encode(map[string]any{"state": "reserved", "record": record})
	}))
	got, e := c.ReserveWorkspace(context.Background(), l, p)
	if e != nil || got.Digest != record.Digest {
		t.Fatal(got, e)
	}
	l.Deadline = time.Now().Add(-time.Second)
	if _, e = c.ReserveWorkspace(context.Background(), l, p); e == nil || calls.Load() != 1 {
		t.Fatal("expired workspace reached the authorization channel")
	}
	b, _ := json.Marshal(record)
	if strings.Contains(string(b), l.Token) {
		t.Fatal("capability persisted in workspace acknowledgement")
	}
}

func TestWorkspaceClientRejectsIndependentlyAlteredAcknowledgements(t *testing.T) {
	for _, kind := range []string{"owner", "job", "request", "app", "repository", "map", "lock", "workspace", "registry", "snapshot", "created", "deadline", "state", "hash"} {
		t.Run(kind, func(t *testing.T) {
			l := claim()
			record, p := clientWorkspaceFixture(l)
			state := "reserved"
			switch kind {
			case "owner":
				record.Document.Owner = "owner-b"
			case "job":
				record.Document.Job = "wrong"
			case "request":
				record.Document.Request = source.Hash([]byte("wrong"))
			case "app":
				record.Document.App = "wrong"
			case "repository":
				record.Document.Repository = "wrong"
			case "map":
				record.Document.Map = source.Hash([]byte("wrong"))
			case "lock":
				record.Document.Lock = source.Hash([]byte("wrong"))
			case "workspace":
				record.Document.Plan.Workspace = "run-" + strings.Repeat("b", 32)
			case "registry":
				record.Document.Plan.Registry = source.Hash([]byte("wrong"))
			case "snapshot":
				record.Document.Plan.Snapshot = source.Hash([]byte("wrong"))
			case "created":
				record.Document.Created = l.Deadline.Format(time.RFC3339Nano)
			case "deadline":
				record.Document.Deadline = l.Deadline.Add(time.Second).Format(time.RFC3339Nano)
			case "state":
				state = "cleaned"
			}
			b, _ := json.Marshal(record.Document)
			record.Digest = source.Hash(b)
			if kind == "hash" {
				record.Digest = source.Hash([]byte("wrong"))
			}
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"state": state, "record": record})
			}))
			if _, e := c.ReserveWorkspace(context.Background(), l, p); e == nil {
				t.Fatal("altered workspace authorization accepted")
			}
		})
	}
}

func TestClaimRequiresWorkspaceProtocol(t *testing.T) {
	for _, protocol := range []string{"", "0.9"} {
		t.Run(protocol, func(t *testing.T) {
			body := wire(claim())
			body["workspace_protocol"] = protocol
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(body) }))
			if _, e := c.Claim(context.Background()); e == nil {
				t.Fatal("unsupported workspace protocol accepted")
			}
		})
	}
}
