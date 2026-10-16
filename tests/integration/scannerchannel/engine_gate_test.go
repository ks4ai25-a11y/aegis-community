//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineprofile"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const gateName = "aegis-scan-0123456789abcdef0123456789abcdef"
const gateID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type gateFixture struct {
	f                                    fixture
	p                                    *engineauthz.Policy
	cfg                                  engineauthz.Config
	request                              engineauthz.Request
	job, source, guard, lock, credential string
}

func privateWrite(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if _, e := os.Lstat(path); e == nil {
		if e = os.Chmod(path, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(path, b, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}

func setupEngineGate(t *testing.T) gateFixture {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("positive operator UID required")
	}
	f := setup(t)
	ctx := context.Background()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	work := filepath.Join(root, "registry")
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	registry := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + work + "\n" + strconv.Itoa(os.Geteuid())))
	engine := source.Hash([]byte("synthetic bound engine"))
	if _, e = f.q.BindEngine("owner-a", engine, registry); e != nil {
		t.Fatal(e)
	}
	journal, e := f.q.BindJournal("owner-a", source.Hash([]byte("synthetic broker root")), source.Hash([]byte("synthetic broker namespace")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.q.BindBroker("owner-a", "worker-a"); e != nil {
		t.Fatal(e)
	}
	j := enqueue(t, f)
	l, e := f.client.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	workspace := "run-0123456789abcdef0123456789abcdef"
	session := filepath.Join(work, workspace)
	if e = os.Mkdir(session, 0700); e != nil {
		t.Fatal(e)
	}
	repo, e := os.OpenRoot(filepath.Join(f.assetRoot, "fixture"))
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	snapshot, e := source.Capture(ctx, repo, l.Map, session)
	if e != nil {
		t.Fatal(e)
	}
	guard := filepath.Join(session, "aegis-guard-fixture")
	if e = os.Mkdir(guard, 0700); e != nil {
		t.Fatal(e)
	}
	guardBytes := []byte("fixture guard claim")
	if runtime.GOARCH == "arm64" {
		guardBytes = []byte("fixture arm64 guard claim")
	}
	privateWrite(t, filepath.Join(guard, "scanner-guard"), guardBytes, 0500)
	raw, _ := json.Marshal(snapshot.Manifest)
	privateWrite(t, filepath.Join(guard, "input-manifest.json"), raw, 0400)
	plan := scanevidence.LaunchPlan{Tool: "bandit", Container: gateName, Engine: engine, Registry: registry, Workspace: workspace, Snapshot: snapshot.Manifest.Digest, Guard: source.Hash(guardBytes), Architecture: runtime.GOARCH, JournalBinding: journal.Digest, JournalNamespace: journal.Document.Namespace}
	if _, e = f.client.ReserveWorkspace(ctx, l, scanevidence.WorkspacePlan{Tool: plan.Tool, Workspace: workspace, Registry: registry, Snapshot: plan.Snapshot}); e != nil {
		t.Fatal(e)
	}
	pin := f.q.Pins["bandit"]
	launch, e := f.client.RegisterLaunch(ctx, l, plan, pin.Version, pin.Image)
	if e != nil {
		t.Fatal(e)
	}
	credentials := filepath.Join(root, "observer")
	if e = os.Mkdir(credentials, 0700); e != nil {
		t.Fatal(e)
	}
	credential := filepath.Join(credentials, "observer.credential")
	if _, e = f.auth.EnrollVerifierFile("owner-a", "engine-observer", 5, engine, registry, credential); e != nil {
		t.Fatal(e)
	}
	lock := filepath.Join(root, "tool-lock.json")
	b, e := os.ReadFile("../../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	privateWrite(t, lock, b, 0600)
	images, _, e := engineauthz.ReadLock(lock)
	if e != nil {
		t.Fatal(e)
	}
	cfg := engineauthz.Config{WorkRoot: work, JournalRoot: filepath.Join(root, "plugin-journal"), EngineDigest: engine, UID: os.Geteuid(), GID: os.Getegid(), Images: images, Live: &engineauthz.LiveConfig{Socket: f.socket, Credential: credential, Owner: "owner-a", Verifier: "engine-observer", Registry: registry, LockPath: lock}}
	if _, e = enginejournal.InitializeEmpty(cfg.JournalRoot, engine); e != nil {
		t.Fatal(e)
	}
	p, e := engineauthz.Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	deadline, _ := time.Parse(time.RFC3339Nano, launch.Document.Deadline)
	create := engineprofile.CreateTracked("bandit", images["bandit"], gateName, snapshot.Path, "", guard, launch.Document.Duration, deadline, cfg.UID, cfg.GID, 123)
	raw, _ = json.Marshal(create)
	request := engineauthz.Request{User: engineauthz.Broker, UserAuthNMethod: "TLS", RequestMethod: "POST", RequestURI: "/v1.55/containers/create?name=" + gateName, RequestBody: raw, RequestHeaders: map[string]string{"Content-Type": "application/json"}}
	return gateFixture{f, p, cfg, request, j.ID, snapshot.Path, guard, lock, credential}
}

func gateCreate(t *testing.T, g gateFixture) {
	t.Helper()
	if !g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("valid bound create refused")
	}
	r := g.request
	r.ResponseStatusCode = 201
	r.ResponseBody = []byte(`{"Id":"` + gateID + `","Warnings":[]}`)
	if !g.p.AuthorizeResponse(r).Allow {
		t.Fatal("create response refused")
	}
}
func gateOperation(method, path string) engineauthz.Request {
	return engineauthz.Request{User: engineauthz.Broker, UserAuthNMethod: "TLS", RequestMethod: method, RequestURI: "/v1.55/containers/" + gateID + path}
}

func TestControllerBoundEngineGateChecksCreateAndStartWithoutReleasing(t *testing.T) {
	g := setupEngineGate(t)
	var before int64
	if e := g.f.s.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&before); e != nil {
		t.Fatal(e)
	}
	gateCreate(t, g)
	start := gateOperation("POST", "/start")
	if !g.p.AuthorizeRequest(start).Allow {
		t.Fatal("valid bound start refused")
	}
	start.ResponseStatusCode = 204
	if !g.p.AuthorizeResponse(start).Allow {
		t.Fatal("start response refused")
	}
	remove := gateOperation("DELETE", "?force=1&v=1")
	if !g.p.AuthorizeRequest(remove).Allow {
		t.Fatal("tracked remove refused")
	}
	remove.ResponseStatusCode = 204
	if !g.p.AuthorizeResponse(remove).Allow {
		t.Fatal("remove response refused")
	}
	o := g.p.Observation()
	if o.Attempts != 1 || o.Unresolved != 0 || o.Unfinished != 0 || o.ControllerBound || o.CleanupAuthorized || o.ExclusiveOrigin {
		t.Fatal("incorrect journal or authority claim")
	}
	var after int64
	if e := g.f.s.DB.QueryRow("SELECT lease_until FROM scanner_dispatch").Scan(&after); e != nil || before != after {
		t.Fatal("plugin renewed lease", e)
	}
	var slots int
	if e := g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&slots); e != nil || slots != 1 {
		t.Fatal("plugin released controller slot", e)
	}
	if e := g.f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}

func TestControllerBoundEngineGateRefusesChangedStateAndBytes(t *testing.T) {
	for _, phase := range []string{"create", "start"} {
		t.Run(phase, func(t *testing.T) {
			for _, kind := range []string{"guard", "manifest", "source", "extra-source", "symlink-guard", "hardlink-guard", "wrong-workspace", "lock", "cancel", "worker-revoked", "observer-revoked", "credential-removed", "controller-unavailable", "lease-expired", "context-cancelled"} {
				t.Run(kind, func(t *testing.T) {
					g := setupEngineGate(t)
					if phase == "start" {
						gateCreate(t, g)
					}
					ctx := context.Background()
					switch kind {
					case "guard":
						privateWrite(t, filepath.Join(g.guard, "scanner-guard"), []byte("changed guard"), 0500)
					case "manifest":
						privateWrite(t, filepath.Join(g.guard, "input-manifest.json"), []byte("{}"), 0400)
					case "source":
						privateWrite(t, filepath.Join(g.source, "query.py"), []byte("changed source"), 0400)
					case "extra-source":
						privateWrite(t, filepath.Join(g.source, "extra.py"), []byte("extra source"), 0400)
					case "symlink-guard":
						if e := os.Rename(filepath.Join(g.guard, "scanner-guard"), filepath.Join(g.guard, "original")); e != nil {
							t.Fatal(e)
						}
						if e := os.Symlink("original", filepath.Join(g.guard, "scanner-guard")); e != nil {
							t.Fatal(e)
						}
					case "hardlink-guard":
						if e := os.Link(filepath.Join(g.guard, "scanner-guard"), filepath.Join(g.guard, "linked-guard")); e != nil {
							t.Fatal(e)
						}
					case "wrong-workspace":
						other := filepath.Join(g.cfg.WorkRoot, "run-"+strings.Repeat("e", 32))
						if e := os.Rename(filepath.Dir(g.source), other); e != nil {
							t.Fatal(e)
						}
					case "lock":
						privateWrite(t, g.lock, []byte("{}"), 0600)
					case "cancel":
						if e := g.f.q.Cancel("owner-a", g.job); e != nil {
							t.Fatal(e)
						}
					case "worker-revoked":
						if e := g.f.auth.Revoke("owner-a", "worker-a"); e != nil {
							t.Fatal(e)
						}
					case "observer-revoked":
						if e := g.f.auth.RevokeVerifier("owner-a", "engine-observer"); e != nil {
							t.Fatal(e)
						}
					case "credential-removed":
						if e := os.Remove(g.credential); e != nil {
							t.Fatal(e)
						}
					case "controller-unavailable":
						if e := os.Remove(g.f.socket); e != nil {
							t.Fatal(e)
						}
					case "lease-expired":
						if _, e := g.f.s.DB.Exec("UPDATE scanner_dispatch SET lease_until=1"); e != nil {
							t.Fatal(e)
						}
					case "context-cancelled":
						c, cancel := context.WithCancel(ctx)
						cancel()
						ctx = c
					}
					r := g.request
					if phase == "start" {
						r = gateOperation("POST", "/start")
					}
					if g.p.AuthorizeRequestContext(ctx, r).Allow {
						t.Fatal("invalid bound operation allowed")
					}
					o := g.p.Observation()
					expected := 0
					if phase == "start" {
						expected = 1
					}
					if o.Attempts != expected || o.Unresolved != 0 {
						t.Fatal("denied operation created intent")
					}
					if phase == "start" {
						remove := gateOperation("DELETE", "?force=1&v=1")
						if !g.p.AuthorizeRequest(remove).Allow {
							t.Fatal("lost cleanup access after refusal")
						}
						remove.ResponseStatusCode = 204
						if !g.p.AuthorizeResponse(remove).Allow {
							t.Fatal("cleanup response refused")
						}
					}
					var slots int
					if e := g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&slots); e != nil || slots != 1 {
						t.Fatal("refusal released held admission", e)
					}
				})
			}
		})
	}
}

func TestControllerBoundEngineGateRetainsConfigurationAcrossRestart(t *testing.T) {
	g := setupEngineGate(t)
	g.p.Close()
	p, e := engineauthz.Open(g.cfg)
	if e != nil {
		t.Fatal("same bound configuration refused", e)
	}
	p.Close()
	for _, kind := range []string{"unbound", "owner", "verifier", "rules", "tools"} {
		t.Run(kind, func(t *testing.T) {
			cfg := g.cfg
			live := *g.cfg.Live
			cfg.Live = &live
			switch kind {
			case "unbound":
				cfg.Live = nil
			case "owner":
				live.Owner = "owner-b"
			case "verifier":
				live.Verifier = "other-observer"
			case "rules":
				live.RulesDigest = source.Hash([]byte("different approved rules"))
			case "tools":
				cfg.Images = map[string]string{"bandit": g.cfg.Images["bandit"]}
			}
			if p, e := engineauthz.Open(cfg); e == nil {
				p.Close()
				t.Fatal("changed sealed configuration accepted")
			}
		})
	}
}

func TestControllerBoundEngineGateRejectsUnregisteredAndMismatchedDescriptor(t *testing.T) {
	for _, kind := range []string{"unregistered-name", "duration", "deadline", "wrong-guard-mode", "wrong-manifest-mode"} {
		t.Run(kind, func(t *testing.T) {
			g := setupEngineGate(t)
			switch kind {
			case "unregistered-name":
				g.request.RequestURI = "/v1.55/containers/create?name=aegis-scan-" + strings.Repeat("f", 32)
			case "duration", "deadline":
				var value map[string]any
				if e := json.Unmarshal(g.request.RequestBody, &value); e != nil {
					t.Fatal(e)
				}
				cmd := value["Cmd"].([]any)
				if kind == "duration" {
					cmd[1] = "119"
				} else {
					cmd[2] = time.Now().UTC().Truncate(time.Second).Add(60 * time.Second).Format(time.RFC3339)
				}
				g.request.RequestBody, _ = json.Marshal(value)
			case "wrong-guard-mode":
				if e := os.Chmod(filepath.Join(g.guard, "scanner-guard"), 0700); e != nil {
					t.Fatal(e)
				}
			case "wrong-manifest-mode":
				if e := os.Chmod(filepath.Join(g.guard, "input-manifest.json"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if g.p.AuthorizeRequest(g.request).Allow {
				t.Fatal("unregistered or mismatched allocation allowed")
			}
			if g.p.Observation().Attempts != 0 {
				t.Fatal("invalid descriptor created durable mutation")
			}
		})
	}
}
