//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func reconcilerDocuments(t *testing.T) (scanevidence.ReconcilerIdentity, scanevidence.ReconciliationSnapshot) {
	t.Helper()
	read := func(name string, out any) {
		t.Helper()
		b, err := os.ReadFile("../../contracts/samples/" + name + ".json")
		if err != nil || json.Unmarshal(b, out) != nil {
			t.Fatal("fixed synthetic client fixture unavailable")
		}
	}
	var v scanevidence.ReconcilerIdentity
	var s scanevidence.ReconciliationSnapshot
	read("ScannerReconcilerIdentityV1", &v)
	read("ScannerReconciliationSnapshotV1", &s)
	now := time.Now().UTC()
	m := s.Membership
	m.Owner = "owner-a"
	m.Binding.Document.Owner = m.Owner
	m.Binding.Document.Created = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	b, _ := json.Marshal(m.Binding.Document)
	m.Binding.Digest = source.Hash(b)
	m.Generation.Binding = m.Binding.Digest
	m.Created = now.Add(-time.Hour).Format(time.RFC3339Nano)
	m.Generation.Deadline = now.Add(-time.Hour + 120*time.Second).Unix()
	m.Lock = source.Hash([]byte("pins"))
	v.Owner = m.Owner
	v.Binding = m.Binding.Digest
	v.Created = now.Add(-time.Minute).Format(time.RFC3339Nano)
	v.Expires = now.Add(10 * time.Minute).Format(time.RFC3339)
	r := scanevidence.ReconciliationRequest{Job: m.Job, Generation: m.Generation.ID, Challenge: s.Challenge}
	updated, err := scanevidence.NewReconciliationSnapshot(m, v, r, now)
	if err != nil {
		t.Fatal(err)
	}
	return v, updated
}

func TestReconcilerClientRejectsChangedOrUnfreshControllerMetadata(t *testing.T) {
	for _, kind := range []string{"role", "binding", "identity-namespace", "challenge", "reconciler", "stale", "future", "membership-hash", "member-namespace", "lock", "open-generation", "release", "engine-write", "null", "alias", "extra"} {
		t.Run(kind, func(t *testing.T) {
			v, prototype := reconcilerDocuments(t)
			base, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "POST" || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
					w.WriteHeader(401)
					return
				}
				switch req.URL.Path {
				case "/internal/v1/scanner/reconciler/identity":
					identity := v
					if kind == "role" {
						identity.Role = scanevidence.CleanupObserverRole
					}
					if kind == "binding" {
						identity.Binding = source.Hash([]byte("other"))
					}
					if kind == "identity-namespace" {
						identity.Namespace = source.Hash([]byte("other"))
					}
					json.NewEncoder(w).Encode(identity)
				case "/internal/v1/scanner/reconciler/context":
					var r scanevidence.ReconciliationRequest
					if json.NewDecoder(req.Body).Decode(&r) != nil {
						t.Error("invalid client request")
						w.WriteHeader(400)
						return
					}
					s := prototype
					s.Challenge = r.Challenge
					s.Observed = time.Now().UTC().Format(time.RFC3339Nano)
					switch kind {
					case "challenge":
						s.Challenge = strings.Repeat("f", 32)
					case "reconciler":
						s.Reconciler = "other"
					case "stale":
						s.Observed = time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
					case "future":
						s.Observed = time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339Nano)
					case "membership-hash":
						s.MembershipHash = source.Hash([]byte("other"))
					case "member-namespace":
						s.Membership.Binding.Document.Namespace = source.Hash([]byte("other"))
					case "lock":
						s.Membership.Lock = source.Hash([]byte("other"))
					case "open-generation":
						s.Membership.Generation.State = "open"
					case "release":
						s.CleanupReleased = true
					case "engine-write":
						s.EngineWrites = true
					}
					wire, _ := json.Marshal(s)
					switch kind {
					case "null":
						wire = []byte("null")
					case "alias":
						wire = []byte(strings.Replace(string(wire), `"metadata_only":true`, `"Metadata_Only":true`, 1))
					case "extra":
						wire = []byte(strings.TrimSuffix(string(wire), "}") + `,"confirmed":true}`)
					}
					w.Write(wire)
				default:
					t.Error("unexpected reconciler operation")
					w.WriteHeader(404)
				}
			}))
			c, err := NewReconciler(base.socket, cred, v.Owner, v.ID, v.Binding, v.Engine, v.Registry, v.Policy, v.Namespace, base.lock)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Snapshot(context.Background(), prototype.Membership.Job, prototype.Membership.Generation.ID); err == nil {
				t.Fatal("untrusted or unfresh controller metadata accepted")
			}
		})
	}
}

func TestReconcilerClientWithdrawalRefusesCachedConnection(t *testing.T) {
	v, prototype := reconcilerDocuments(t)
	var calls atomic.Int32
	base, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); json.NewEncoder(w).Encode(v) }))
	c, err := NewReconciler(base.socket, cred, v.Owner, v.ID, v.Binding, v.Engine, v.Registry, v.Policy, v.Namespace, base.lock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	if err = os.Remove(cred); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Snapshot(context.Background(), prototype.Membership.Job, prototype.Membership.Generation.ID); err == nil || calls.Load() != before {
		t.Fatal("cached connection bypassed credential withdrawal")
	}
}
