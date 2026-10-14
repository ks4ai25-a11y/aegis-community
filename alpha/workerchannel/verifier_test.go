// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func verifierDocuments(t *testing.T) (scanevidence.VerifierIdentity, scanevidence.CleanupContextRecord) {
	t.Helper()
	l := claim()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	deadline := l.Deadline.UTC().Format(time.RFC3339)
	engine, registry := source.Hash([]byte("engine")), source.Hash([]byte("registry"))
	snapshot := source.Hash([]byte("snapshot"))
	w := scanevidence.Workspace{Schema: "1.0", Owner: l.Job.Owner, Job: l.Job.ID, Request: l.Job.RequestDigest, App: l.Job.Input.App, Repository: l.Job.Input.Repository, Map: l.Job.Input.MapDigest, Lock: l.Job.LockDigest, Plan: scanevidence.WorkspacePlan{Tool: "bandit", Workspace: "run-" + strings.Repeat("a", 32), Registry: registry, Snapshot: snapshot}, Created: stamp, Deadline: deadline}
	wb, _ := json.Marshal(w)
	p := scanevidence.LaunchPlan{Tool: "bandit", Container: "aegis-scan-" + strings.Repeat("b", 32), Engine: engine, Workspace: w.Plan.Workspace, Registry: registry, Snapshot: snapshot, Guard: l.Guards.AMD64, Architecture: "amd64"}
	launch := scanevidence.Launch{Schema: "1.1", Owner: w.Owner, Job: w.Job, Request: w.Request, App: w.App, Repository: w.Repository, Map: w.Map, Lock: w.Lock, Version: "1.9.4", Image: source.Hash([]byte("image")), Profile: "repo_offline-network-none-v1", Duration: 120, Plan: p, Created: stamp, Deadline: deadline, GuardSet: l.Guards.Digest, GuardProtocol: l.Guards.Protocol}
	lb, _ := json.Marshal(launch)
	d := scanevidence.CleanupContext{Schema: "1.0", Verifier: "verifier-a", Owner: w.Owner, Job: w.Job, Request: w.Request, App: w.App, Repository: w.Repository, Map: w.Map, Lock: w.Lock, Created: l.Job.Created, Worker: "worker-a", JobState: "running", DispatchState: "active", Deadline: deadline, LeaseUntil: now.Add(10 * time.Second).Format(time.RFC3339), GuardSet: l.Guards.Digest, Engine: engine, Registry: registry, Tools: []string{"bandit"}, Workspaces: []scanevidence.WorkspaceRecord{{Digest: source.Hash(wb), Document: w}}, Launches: []scanevidence.LaunchRecord{{Digest: source.Hash(lb), Document: launch}}, Observed: stamp, MetadataOnly: true, CleanupRequired: true}
	r, e := scanevidence.NewCleanupContext(d)
	if e != nil {
		t.Fatal("invalid client fixture", e)
	}
	v := scanevidence.VerifierIdentity{Schema: "1.0", Role: scanevidence.CleanupObserverRole, ID: d.Verifier, Owner: d.Owner, Engine: engine, Registry: registry, State: "active", Created: now.Add(-time.Minute).Format(time.RFC3339Nano), Expires: now.Add(5 * time.Minute).Format(time.RFC3339)}
	return v, r
}
func resealVerifierContext(r *scanevidence.CleanupContextRecord) {
	for i := range r.Document.Workspaces {
		b, _ := json.Marshal(r.Document.Workspaces[i].Document)
		r.Document.Workspaces[i].Digest = source.Hash(b)
	}
	for i := range r.Document.Launches {
		b, _ := json.Marshal(r.Document.Launches[i].Document)
		r.Document.Launches[i].Digest = source.Hash(b)
	}
	b, _ := json.Marshal(r.Document)
	r.Digest = source.Hash(b)
}
func TestVerifierClientPinsScopeRereadsCredentialsAndNeverClaimsCleanup(t *testing.T) {
	v, r := verifierDocuments(t)
	var count atomic.Int32
	base, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		count.Add(1)
		if req.Method != "POST" || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || req.Header.Get("Cookie") != "" || req.Header.Get("Origin") != "" {
			w.WriteHeader(401)
			return
		}
		switch req.URL.Path {
		case "/internal/v1/scanner/verifier/identity":
			json.NewEncoder(w).Encode(v)
		case "/internal/v1/scanner/verifier/context":
			var body struct {
				Job string `json:"job_id"`
			}
			if json.NewDecoder(req.Body).Decode(&body) != nil || body.Job != r.Document.Job {
				t.Error("job identity changed")
			}
			json.NewEncoder(w).Encode(r)
		default:
			w.WriteHeader(404)
		}
	}))
	client, e := NewVerifier(base.socket, cred, v.Owner, v.ID, v.Engine, v.Registry, r.Document.Lock)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	got, e := client.Context(context.Background(), r.Document.Job)
	if e != nil || got.Digest != r.Digest || got.Document.CleanupConfirmed || got.Document.LeasesExcluded || got.Document.LateStartExcluded {
		t.Fatal("metadata promoted or detached", e)
	}
	before := count.Load()
	os.Chmod(filepath.Dir(cred), 0755)
	if _, e = client.Identity(context.Background()); e == nil {
		t.Fatal("public parent accepted")
	}
	if count.Load() != before {
		t.Fatal("request preceded parent check")
	}
	os.Chmod(filepath.Dir(cred), 0700)
	os.WriteFile(cred, []byte(strings.Repeat("b", 64)+"\n"), 0600)
	if _, e = client.Identity(context.Background()); e == nil {
		t.Fatal("credential cached across replacement")
	}
}
func TestVerifierClientRejectsWrongIdentityAndHostileContext(t *testing.T) {
	for _, kind := range []string{"role", "owner", "id", "engine", "registry", "expiry", "unknown", "duplicate", "alias", "missing_false_flag", "null", "trailing", "noncanonical", "oversize", "context_digest", "context_owner", "context_engine", "context_lock", "context_deadline", "context_map", "context_guard_set", "duplicate_launch", "cleanup_claim", "lease_claim", "late_start_claim", "stale", "future", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			v, r := verifierDocuments(t)
			var calls atomic.Int32
			base, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if strings.HasSuffix(req.URL.Path, "/identity") {
					out := v
					switch kind {
					case "role":
						out.Role = "offline-scanner-worker"
					case "owner":
						out.Owner = "owner-b"
					case "id":
						out.ID = "other-verifier"
					case "engine":
						out.Engine = source.Hash([]byte("other"))
					case "registry":
						out.Registry = source.Hash([]byte("other"))
					case "expiry":
						out.Expires = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
					}
					json.NewEncoder(w).Encode(out)
					return
				}
				out := r
				// Deep copy nested records before preparing a hostile response.
				raw, _ := json.Marshal(r)
				json.Unmarshal(raw, &out)
				switch kind {
				case "context_owner":
					out.Document.Owner = "owner-b"
				case "context_engine":
					out.Document.Engine = source.Hash([]byte("other engine"))
				case "context_lock":
					out.Document.Lock = source.Hash([]byte("other lock"))
				case "context_deadline":
					out.Document.Launches[0].Document.Deadline = time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)
				case "context_map":
					out.Document.Workspaces[0].Document.Map = source.Hash([]byte("other map"))
				case "context_guard_set":
					out.Document.Launches[0].Document.GuardSet = source.Hash([]byte("other guard set"))
				case "duplicate_launch":
					out.Document.Launches = append(out.Document.Launches, out.Document.Launches[0])
				case "cleanup_claim":
					out.Document.CleanupConfirmed = true
				case "lease_claim":
					out.Document.LeasesExcluded = true
				case "late_start_claim":
					out.Document.LateStartExcluded = true
				case "stale":
					now := time.Now().UTC()
					out.Document.Created = now.Add(-time.Minute).Format(time.RFC3339Nano)
					out.Document.Workspaces[0].Document.Created = now.Add(-50 * time.Second).Format(time.RFC3339Nano)
					out.Document.Launches[0].Document.Created = now.Add(-40 * time.Second).Format(time.RFC3339Nano)
					out.Document.Observed = now.Add(-30 * time.Second).Format(time.RFC3339Nano)
				case "future":
					out.Document.Observed = time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano)
				case "redirect":
					http.Redirect(w, req, "http://not-allowed.invalid/next", 307)
					return
				}
				resealVerifierContext(&out)
				if kind == "context_digest" {
					out.Digest = source.Hash([]byte("wrong digest"))
				}
				b, _ := json.Marshal(out)
				switch kind {
				case "unknown":
					b = append(b[:len(b)-1], []byte(`,"lease_token":"unsupported"}`)...)
				case "duplicate":
					b = bytes.Replace(b, []byte(`"cleanup_confirmed":false`), []byte(`"cleanup_confirmed":false,"cleanup_confirmed":false`), 1)
				case "alias":
					b = bytes.Replace(b, []byte(`"cleanup_confirmed"`), []byte(`"Cleanup_confirmed"`), 1)
				case "missing_false_flag":
					b = bytes.Replace(b, []byte(`,"cleanup_confirmed":false`), nil, 1)
				case "null":
					b = bytes.Replace(b, []byte(`"cleanup_confirmed":false`), []byte(`"cleanup_confirmed":null`), 1)
				case "trailing":
					b = append(b, []byte(" {}")...)
				case "noncanonical":
					var pretty bytes.Buffer
					json.Indent(&pretty, b, "", " ")
					b = pretty.Bytes()
				case "oversize":
					b = []byte(strings.Repeat("x", (64<<10)+1))
				}
				w.Write(b)
			}))
			client, e := NewVerifier(base.socket, cred, v.Owner, v.ID, v.Engine, v.Registry, r.Document.Lock)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			if _, e = client.Context(context.Background(), r.Document.Job); e == nil {
				t.Fatal("hostile verifier response accepted", kind)
			}
			if kind == "redirect" && calls.Load() != 2 {
				t.Fatal("redirect followed")
			}
		})
	}
}
