//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scannerchannelacceptance

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineprofile"
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"aegis.local/source/privateipc"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Forward the actual private controller response, but lose the first successful
// completion acknowledgement after it has committed. No native engine retry.
func completionAckProxy(t *testing.T, target, path string) string {
	t.Helper()
	parent, e := os.MkdirTemp("/tmp", "aack-")
	if e != nil {
		t.Fatal(e)
	}
	parent, e = filepath.EvalSymlinks(parent)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	path = filepath.Join(parent, "proxy.sock")
	listener, e := privateipc.Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", target)
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	var lost atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		request.RequestURI = ""
		request.URL.Scheme = "http"
		request.URL.Host = "unix"
		response, e := client.Do(request)
		if e != nil {
			w.WriteHeader(503)
			return
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 32769))
		if e != nil || len(body) > 32768 {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/internal/v1/scanner/authorizer/complete" && response.StatusCode == 200 && lost.CompareAndSwap(false, true) {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		w.Write(body)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return path
}

func setupAdmittedEngineGate(t *testing.T, dropCompletionAck bool) gateFixture {
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
	namespace, e := workspace.InitializeRegistryNamespace(ctx, work)
	if e != nil {
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
	credentials := filepath.Join(root, "authorizer")
	if e = os.Mkdir(credentials, 0700); e != nil {
		t.Fatal(e)
	}
	credential := filepath.Join(credentials, "authorizer.credential")
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
	controllerSocket := f.socket
	if dropCompletionAck {
		controllerSocket = completionAckProxy(t, f.socket, filepath.Join(root, "proxy.sock"))
	}
	cfg := engineauthz.Config{WorkRoot: work, JournalRoot: filepath.Join(root, "plugin-journal"), EngineDigest: engine, UID: os.Geteuid(), GID: os.Getegid(), Images: images, Admitted: &engineauthz.AdmittedConfig{Socket: controllerSocket, Credential: credential, Owner: "owner-a", Authorizer: "engine-authorizer", Registry: registry, Namespace: namespace, LockPath: lock}}
	if _, e = enginejournal.InitializeEmpty(cfg.JournalRoot, engine); e != nil {
		t.Fatal(e)
	}
	policy, e := engineauthz.AdmittedPolicyDigest(cfg, *cfg.Admitted)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.auth.EnrollAuthorizerFile("owner-a", "engine-authorizer", 5, engine, registry, policy, credential); e != nil {
		t.Fatal(e)
	}
	if _, e = f.q.BindMutationAuthorizer("owner-a", "engine-authorizer", namespace); e != nil {
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
	p, e := engineauthz.Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	deadline, _ := time.Parse(time.RFC3339Nano, launch.Document.Deadline)
	create := engineprofile.CreateTracked("bandit", images["bandit"], gateName, snapshot.Path, "", guard, launch.Document.Duration, deadline, cfg.UID, cfg.GID, 123)
	raw, _ = json.Marshal(create)
	request := engineauthz.Request{User: engineauthz.Broker, UserAuthNMethod: "TLS", RequestPeerCertificates: nativeTestPeer(engineauthz.Broker), RequestMethod: "POST", RequestURI: "/v1.55/containers/create?name=" + gateName, RequestBody: raw, RequestHeaders: map[string]string{"Content-Type": "application/json"}}
	return gateFixture{f, p, cfg, request, j.ID, snapshot.Path, guard, lock, credential}
}

func TestAdmittedNativeGatePersistsBeforeAllowAndCompletesAfterLocalSync(t *testing.T) {
	g := setupAdmittedEngineGate(t, false)
	if !g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("registered admitted create refused")
	}
	var state, response string
	if e := g.f.s.DB.QueryRow("SELECT state,response_digest FROM scanner_mutation_intents WHERE operation='create'").Scan(&state, &response); e != nil || state != "pending" || response != "" {
		t.Fatal("Allow preceded durable controller admission", e)
	}
	raw, e := os.ReadFile(filepath.Join(g.cfg.JournalRoot, gateName, "create.pending.json"))
	if e != nil {
		t.Fatal(e)
	}
	var local struct {
		Document struct {
			Controller scanevidence.MutationIntent `json:"controller_intent"`
		} `json:"document"`
	}
	if json.Unmarshal(raw, &local) != nil || !local.Document.Controller.Valid() {
		t.Fatal("local pending request lacks exact controller identity")
	}
	callback := g.request
	callback.ResponseStatusCode = 201
	callback.ResponseBody = []byte(`{"Id":"` + gateID + `","Warnings":[]}`)
	if !g.p.AuthorizeResponse(callback).Allow {
		t.Fatal("native create response refused")
	}
	raw, e = os.ReadFile(filepath.Join(g.cfg.JournalRoot, gateName, "create.response.json"))
	if e != nil {
		t.Fatal(e)
	}
	var durable struct {
		Digest string `json:"digest"`
	}
	if json.Unmarshal(raw, &durable) != nil {
		t.Fatal("native response missing")
	}
	if e = g.f.s.DB.QueryRow("SELECT state,response_digest FROM scanner_mutation_intents WHERE operation='create'").Scan(&state, &response); e != nil || state != "completed" || response != durable.Digest {
		t.Fatal("controller completion was not bound to durable native response", e)
	}
	start := gateOperation("POST", "/start")
	if !g.p.AuthorizeRequest(start).Allow {
		t.Fatal("admitted start refused")
	}
	start.ResponseStatusCode = 204
	if !g.p.AuthorizeResponse(start).Allow {
		t.Fatal("start completion refused")
	}
	if e = g.f.q.Cancel("owner-a", g.job); e != nil {
		t.Fatal(e)
	}
	if g.p.AuthorizeRequest(gateOperation("POST", "/start")).Allow {
		t.Fatal("late start survived generation closure")
	}
	remove := gateOperation("DELETE", "?force=1&v=1")
	if !g.p.AuthorizeRequest(remove).Allow {
		t.Fatal("tracked cleanup after cancellation refused")
	}
	remove.ResponseStatusCode = 204
	if !g.p.AuthorizeResponse(remove).Allow {
		t.Fatal("remove completion refused")
	}
	var pending int
	if e = g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents WHERE state='pending'").Scan(&pending); e != nil || pending != 0 {
		t.Fatal(e)
	}
	if _, e = g.f.s.DB.Exec("DELETE FROM scanner_dispatch"); e == nil {
		t.Fatal("settled native gate released unverified dispatch")
	}
}
func TestAdmittedNativeCompletionLostAckRetriesOnlyMetadata(t *testing.T) {
	g := setupAdmittedEngineGate(t, true)
	if !g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("create refused")
	}
	callback := g.request
	callback.ResponseStatusCode = 201
	callback.ResponseBody = []byte(`{"Id":"` + gateID + `","Warnings":[]}`)
	if g.p.AuthorizeResponse(callback).Allow {
		t.Fatal("lost completion acknowledgement accepted")
	}
	var state string
	if e := g.f.s.DB.QueryRow("SELECT state FROM scanner_mutation_intents WHERE operation='create'").Scan(&state); e != nil || state != "completed" {
		t.Fatal("proxy did not lose a committed acknowledgement", e)
	}
	if g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("uncertain response permitted native mutation replay")
	}
	changed := callback
	changed.ResponseStatusCode = 500
	if g.p.AuthorizeResponse(changed).Allow {
		t.Fatal("changed response replay accepted")
	}
	if !g.p.AuthorizeResponse(callback).Allow {
		t.Fatal("exact completion acknowledgement could not be reconciled")
	}
	var n int
	if e := g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 1 {
		t.Fatal("completion replay created another intent", e)
	}
}
func TestAdmittedNativeGateKeepsUnknownAfterControllerAdmissionFailure(t *testing.T) {
	g := setupAdmittedEngineGate(t, false)
	if _, e := g.f.s.DB.Exec("CREATE TRIGGER reject_admission BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	if g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("failed durable admission allowed native create")
	}
	if _, e := g.f.s.DB.Exec("DROP TRIGGER reject_admission"); e != nil {
		t.Fatal(e)
	}
	if g.p.AuthorizeRequest(g.request).Allow {
		t.Fatal("native create was retried after uncertain admission")
	}
	var n int
	if e := g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 0 {
		t.Fatal("failed admission committed", e)
	}
	if g.p.Observation().Unresolved != 1 {
		t.Fatal("local unknown intent was discarded")
	}
}

func TestAdmittedNativeGateRefusesWithdrawnScopeAndChangedSource(t *testing.T) {
	for _, kind := range []string{"cancel", "revoke", "expired-lease", "source", "namespace"} {
		t.Run(kind, func(t *testing.T) {
			g := setupAdmittedEngineGate(t, false)
			switch kind {
			case "cancel":
				if e := g.f.q.Cancel("owner-a", g.job); e != nil {
					t.Fatal(e)
				}
			case "revoke":
				if e := g.f.auth.RevokeAuthorizer("owner-a", "engine-authorizer"); e != nil {
					t.Fatal(e)
				}
			case "expired-lease":
				future := time.Now().Add(20 * time.Second)
				g.f.q.Now = func() time.Time { return future }
			case "source":
				privateWrite(t, filepath.Join(g.source, "query.py"), []byte("changed source"), 0400)
			case "namespace":
				if e := os.Rename(g.cfg.WorkRoot, g.cfg.WorkRoot+"-original"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(g.cfg.WorkRoot, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if g.p.AuthorizeRequest(g.request).Allow {
				t.Fatal("changed authority or bytes admitted")
			}
			var n int
			if e := g.f.s.DB.QueryRow("SELECT count(*) FROM scanner_mutation_intents").Scan(&n); e != nil || n != 0 {
				t.Fatal("denied precondition created controller obligation", e)
			}
		})
	}
}
func TestAdmittedNativeSettledJournalRestartsOnlyUnderExactSelection(t *testing.T) {
	g := setupAdmittedEngineGate(t, false)
	gateCreate(t, g)
	remove := gateOperation("DELETE", "?force=1&v=1")
	if !g.p.AuthorizeRequest(remove).Allow {
		t.Fatal("cleanup refused")
	}
	remove.ResponseStatusCode = 204
	if !g.p.AuthorizeResponse(remove).Allow {
		t.Fatal("cleanup response refused")
	}
	g.p.Close()
	downgrade := g.cfg
	downgrade.Admitted = nil
	if p, e := engineauthz.Open(downgrade); e == nil {
		p.Close()
		t.Fatal("used journal downgraded to unbound mode")
	}
	reopened, e := engineauthz.Open(g.cfg)
	if e != nil {
		t.Fatal("exact settled native selection failed to reopen", e)
	}
	defer reopened.Close()
	if reopened.AuthorizeRequest(g.request).Allow {
		t.Fatal("restarted gate repeated used native allocation")
	}
	if _, e = g.f.s.DB.Exec("DELETE FROM scanner_dispatch"); e == nil {
		t.Fatal("journal restart freed controller hold")
	}
}
