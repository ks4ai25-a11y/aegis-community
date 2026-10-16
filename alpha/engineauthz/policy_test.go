// SPDX-License-Identifier: Apache-2.0
package engineauthz

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineprofile"
	"aegis.local/source"
	"bytes"
	"encoding/json"
	"github.com/moby/moby/api/types/container"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testName = "aegis-scan-0123456789abcdef0123456789abcdef"
const testID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const testImage = "ghcr.io/pycqa/bandit/bandit@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func fixture(t *testing.T) (*Policy, Config, Request) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	work := filepath.Join(root, "work")
	if os.Mkdir(work, 0700) != nil {
		t.Fatal("work")
	}
	for _, d := range []string{"source", "guard"} {
		if os.Mkdir(filepath.Join(work, d), 0700) != nil {
			t.Fatal("dir")
		}
	}
	cfg := Config{WorkRoot: work, JournalRoot: filepath.Join(root, "journal"), EngineDigest: source.Hash([]byte("authz-test-engine")), UID: 10001, GID: 10001, Images: map[string]string{"bandit": testImage}}
	if _, e = enginejournal.InitializeEmpty(cfg.JournalRoot, cfg.EngineDigest); e != nil {
		t.Fatal(e)
	}
	p, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	profile := engineprofile.CreateTracked("bandit", testImage, testName, filepath.Join(work, "source"), "", filepath.Join(work, "guard"), 120, time.Now().UTC().Add(120*time.Second), cfg.UID, cfg.GID, 123)
	b, _ := json.Marshal(profile)
	return p, cfg, Request{User: Broker, UserAuthNMethod: "TLS", RequestMethod: "POST", RequestURI: api + "/containers/create?name=" + testName, RequestBody: b, RequestHeaders: map[string]string{"Content-Type": "application/json"}}
}
func must(t *testing.T, d Decision, allow bool) {
	t.Helper()
	if d.Allow != allow {
		t.Fatalf("decision %+v, want %v", d, allow)
	}
}
func call(method, path string) Request {
	return Request{User: Broker, UserAuthNMethod: "TLS", RequestMethod: method, RequestURI: api + path}
}
func created(t *testing.T, p *Policy, r Request) {
	t.Helper()
	must(t, p.AuthorizeRequest(r), true)
	o := p.Observation()
	if o.Unfinished != 1 || o.Unresolved != 1 || o.ExclusiveOrigin || o.CleanupAuthorized || o.ControllerBound {
		t.Fatalf("intent missing or inflated authority: %+v", o)
	}
	r.ResponseStatusCode = 201
	r.ResponseBody = []byte(`{"Id":"` + testID + `","Warnings":[]}`)
	must(t, p.AuthorizeResponse(r), true)
}
func TestLifecycleRequiresExactIntentAndResponse(t *testing.T) {
	p, _, r := fixture(t)
	created(t, p, r)
	start := call("POST", "/containers/"+testID+"/start")
	must(t, p.AuthorizeRequest(start), true)
	// A replay and a conflicting write cannot get a second ticket.
	must(t, p.AuthorizeRequest(start), false)
	wrong := start
	wrong.RequestURI = strings.Replace(wrong.RequestURI, testID, strings.Repeat("a", 64), 1)
	wrong.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(wrong), false)
	if p.Observation().Unresolved != 1 {
		t.Fatal("wrong response cleared intent")
	}
	start.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(start), true)
	must(t, p.AuthorizeRequest(start), false)
	remove := call("DELETE", "/containers/"+testID+"?force=1&v=1")
	must(t, p.AuthorizeRequest(remove), true)
	remove.ResponseStatusCode = 204
	must(t, p.AuthorizeResponse(remove), true)
	o := p.Observation()
	if o.Unresolved != 0 || o.Unfinished != 0 || o.Attempts != 1 || o.ExclusiveOrigin || o.CleanupAuthorized {
		t.Fatalf("bad settled observation: %+v", o)
	}
	must(t, p.AuthorizeRequest(remove), false)
}
func TestUnansweredOrFailedMutationsPersistQuarantine(t *testing.T) {
	for _, phase := range []string{"no-response", "bad-create-id", "create-error", "truncated-create", "start-error", "remove-error", "remove-404", "callback-unwritten"} {
		t.Run(phase, func(t *testing.T) {
			p, cfg, r := fixture(t)
			must(t, p.AuthorizeRequest(r), true)
			r.ResponseStatusCode = 201
			r.ResponseBody = []byte(`{"Id":"` + testID + `","Warnings":[]}`)
			switch phase {
			case "no-response":
			case "bad-create-id":
				r.ResponseBody = []byte(`{"Id":"short"}`)
				must(t, p.AuthorizeResponse(r), false)
			case "create-error":
				r.ResponseStatusCode = 500
				must(t, p.AuthorizeResponse(r), false)
			case "truncated-create":
				r.ResponseBody = r.ResponseBody[:len(r.ResponseBody)-1]
				must(t, p.AuthorizeResponse(r), false)
			default:
				must(t, p.AuthorizeResponse(r), true)
				if phase == "start-error" {
					r = call("POST", "/containers/"+testID+"/start")
				} else {
					r = call("DELETE", "/containers/"+testID+"?force=1&v=1")
				}
				must(t, p.AuthorizeRequest(r), true)
				r.ResponseStatusCode = 500
				if phase == "remove-404" {
					r.ResponseStatusCode = 404
					r.ResponseBody = []byte(`{"message":"No such container"}`)
					must(t, p.AuthorizeResponse(r), false)
				} else if phase == "callback-unwritten" {
					r.ResponseStatusCode = 200
					must(t, p.AuthorizeResponse(r), false)
				} else {
					must(t, p.AuthorizeResponse(r), false)
				}
			}
			p.Close()
			q, e := Open(cfg)
			if e == nil {
				q.Close()
				t.Fatal("unresolved restart accepted")
			}

			if _, e := enginejournal.InitializeEmpty(cfg.JournalRoot, cfg.EngineDigest); e == nil {
				t.Fatal("used journal reinitialized")
			}
		})
	}
}
func TestPrincipalPathAndReadBoundaries(t *testing.T) {
	p, _, r := fixture(t)
	for _, user := range []string{"", Observer, "aegis-engine-admin", "root", Broker + " "} {
		x := r
		x.User = user
		must(t, p.AuthorizeRequest(x), false)
	}
	for _, method := range []string{"", "tls", "Unix", "Basic"} {
		x := r
		x.UserAuthNMethod = method
		must(t, p.AuthorizeRequest(x), false)
	}
	for _, path := range []string{"/info", "/v1.56/info", api + "/grpc", api + "/build", api + "/containers/prune", api + "/images/create", api + "/containers/json", api + "/info?", api + "/info?x=1", api + "/in%66o", api + "/containers/../info", "https://evil.example" + api + "/info"} {
		x := r
		x.RequestMethod = "GET"
		x.RequestBody = nil
		x.RequestURI = path
		must(t, p.AuthorizeRequest(x), false)
	}
	for _, user := range []string{Broker, Observer} {
		for _, path := range []string{"/info", "/images/" + testImage + "/json"} {
			x := call("GET", path)
			x.User = user
			must(t, p.AuthorizeRequest(x), true)
			must(t, p.AuthorizeResponse(x), true)
		}
	}
	must(t, p.AuthorizeRequest(call("POST", "/containers/"+testID+"/start")), false)
	created(t, p, r)
	for _, user := range []string{Broker, Observer} {
		x := call("GET", "/containers/"+testID+"/json")
		x.User = user
		must(t, p.AuthorizeRequest(x), true)
	}
	for _, user := range []string{Broker, Observer} {
		x := call("GET", "/containers/"+testName+"/json")
		x.User = user
		must(t, p.AuthorizeRequest(x), true)
	}
	must(t, p.AuthorizeRequest(call("GET", "/containers/aegis-scan-"+strings.Repeat("b", 32)+"/json")), false)
	f, _ := json.Marshal(map[string]map[string]bool{"name": {"^/" + testName + "$": true}})
	x := call("GET", "/containers/json?"+url.Values{"all": {"1"}, "filters": {string(f)}}.Encode())
	x.User = Observer
	must(t, p.AuthorizeRequest(x), true)
	for _, path := range []string{"/containers/" + testID + "/attach?stderr=1&stdout=1&stream=1", "/containers/" + testID + "/wait?condition=next-exit", "/containers/" + testID + "/wait?condition=removed"} {
		x := call("POST", path)
		must(t, p.AuthorizeRequest(x), true)
		x.User = Observer
		must(t, p.AuthorizeRequest(x), false)
	}
	for _, path := range []string{"/containers/" + testID + "/attach?stderr=1&stdin=1&stdout=1&stream=1", "/containers/" + testID + "/wait?condition=not-running", "/containers/" + strings.Repeat("b", 64) + "/start", "/containers/" + testID + "/exec"} {
		must(t, p.AuthorizeRequest(call("POST", path)), false)
	}
}
func TestContainerProfileRefusalsBeforeAnyIntent(t *testing.T) {
	mutations := map[string]func(*container.CreateRequest){
		"privileged":     func(c *container.CreateRequest) { c.HostConfig.Privileged = true },
		"rw-root":        func(c *container.CreateRequest) { c.HostConfig.ReadonlyRootfs = false },
		"auto-remove":    func(c *container.CreateRequest) { c.HostConfig.AutoRemove = true },
		"root-user":      func(c *container.CreateRequest) { c.User = "0:0" },
		"other-user":     func(c *container.CreateRequest) { c.User = "10002:10002" },
		"network":        func(c *container.CreateRequest) { c.HostConfig.NetworkMode = "host" },
		"ipc":            func(c *container.CreateRequest) { c.HostConfig.IpcMode = "host" },
		"pid":            func(c *container.CreateRequest) { c.HostConfig.PidMode = "host" },
		"caps":           func(c *container.CreateRequest) { c.HostConfig.CapDrop = nil },
		"cap-add":        func(c *container.CreateRequest) { c.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"security":       func(c *container.CreateRequest) { c.HostConfig.SecurityOpt = nil },
		"memory":         func(c *container.CreateRequest) { c.HostConfig.Memory = 0 },
		"swap":           func(c *container.CreateRequest) { c.HostConfig.MemorySwap = -1 },
		"pids":           func(c *container.CreateRequest) { c.HostConfig.PidsLimit = nil },
		"cpu":            func(c *container.CreateRequest) { c.HostConfig.NanoCPUs = 0 },
		"command":        func(c *container.CreateRequest) { c.Cmd = []string{"sh", "-c", "id"} },
		"entrypoint":     func(c *container.CreateRequest) { c.Entrypoint = []string{"/bin/sh"} },
		"image":          func(c *container.CreateRequest) { c.Image = "bandit:latest" },
		"tool":           func(c *container.CreateRequest) { c.Cmd[0] = "arbitrary" },
		"env":            func(c *container.CreateRequest) { c.Env = append(c.Env, "TOKEN=secret") },
		"stdin":          func(c *container.CreateRequest) { c.OpenStdin = true },
		"tty":            func(c *container.CreateRequest) { c.Tty = true },
		"writable-mount": func(c *container.CreateRequest) { c.HostConfig.Mounts[0].ReadOnly = false },
		"mount-outside":  func(c *container.CreateRequest) { c.HostConfig.Mounts[0].Source = "/" },
		"mount-target":   func(c *container.CreateRequest) { c.HostConfig.Mounts[0].Target = "/var/run/docker.sock" },
		"extra-mount": func(c *container.CreateRequest) {
			c.HostConfig.Mounts = append(c.HostConfig.Mounts, c.HostConfig.Mounts[0])
		},
		"tmpfs": func(c *container.CreateRequest) { c.HostConfig.Tmpfs["/tmp"] = "rw,exec" },
		"deadline-past": func(c *container.CreateRequest) {
			c.Cmd[2] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		},
		"deadline-later": func(c *container.CreateRequest) {
			c.Cmd[2] = time.Now().Add(16 * time.Minute).UTC().Format(time.RFC3339Nano)
		},
		"duration":       func(c *container.CreateRequest) { c.Cmd[1] = "121" },
		"operator-label": func(c *container.CreateRequest) { c.Labels["io.aegis.operator_pid"] = "01" },
		"extra-label":    func(c *container.CreateRequest) { c.Labels["evil"] = "value" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p, _, r := fixture(t)
			var c container.CreateRequest
			_ = json.Unmarshal(r.RequestBody, &c)
			mutate(&c)
			r.RequestBody, _ = json.Marshal(c)
			must(t, p.AuthorizeRequest(r), false)
			if p.Observation().Attempts != 0 {
				t.Fatal("invalid profile allocated")
			}
		})
	}
	for _, kind := range []string{"duplicate", "case-alias", "unknown", "omitted", "null", "invalid-utf8", "trailing", "oversize", "wrong-type", "non-json", "duplicate-query", "encoded-query", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			p, cfg, r := fixture(t)
			switch kind {
			case "duplicate":
				r.RequestBody = bytes.Replace(r.RequestBody, []byte(`"Image":`), []byte(`"Image":"bad","Image":`), 1)
			case "case-alias":
				r.RequestBody = bytes.Replace(r.RequestBody, []byte(`"Image":`), []byte(`"image":`), 1)
			case "unknown":
				r.RequestBody = append([]byte(`{"unknown":true,`), r.RequestBody[1:]...)
			case "omitted":
				r.RequestBody = bytes.Replace(r.RequestBody, []byte(`"ReadonlyRootfs":true,`), nil, 1)
			case "null":
				r.RequestBody = bytes.Replace(r.RequestBody, []byte(`"ReadonlyRootfs":true`), []byte(`"ReadonlyRootfs":null`), 1)
			case "invalid-utf8":
				r.RequestBody = append(r.RequestBody, 255)
			case "trailing":
				r.RequestBody = append(r.RequestBody, []byte(` {}`)...)
			case "oversize":
				r.RequestBody = bytes.Repeat([]byte(" "), 65537)
			case "wrong-type":
				r.RequestBody = []byte(`[]`)
			case "non-json":
				r.RequestHeaders["Content-Type"] = "text/plain"
			case "duplicate-query":
				r.RequestURI += "&name=" + testName
			case "encoded-query":
				r.RequestURI = strings.Replace(r.RequestURI, "name=", "%6eame=", 1)
			case "symlink":
				os.Rename(filepath.Join(cfg.WorkRoot, "source"), filepath.Join(cfg.WorkRoot, "original"))
				if os.Symlink(filepath.Join(cfg.WorkRoot, "original"), filepath.Join(cfg.WorkRoot, "source")) != nil {
					t.Fatal("symlink")
				}
			}
			must(t, p.AuthorizeRequest(r), false)
			if p.Observation().Attempts != 0 {
				t.Fatal("invalid request allocated")
			}
		})
	}
}
func TestConcurrentCreateHasOneDurableWinner(t *testing.T) {
	p, _, r := fixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			d := p.AuthorizeRequest(r)
			if d.Allow {
				mu.Lock()
				count++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if count != 1 || p.Observation().Unresolved != 1 {
		t.Fatalf("winners %d", count)
	}
}
func TestNativePluginProtocolFailsClosed(t *testing.T) {
	p, _, r := fixture(t)
	for _, tc := range []struct {
		method, path, body string
		allowed            bool
	}{
		{"POST", "/Plugin.Activate", `{}`, true},
		{"POST", "/Plugin.Activate", ``, true},
		{"GET", "/Plugin.Activate", `{}`, false},
		{"POST", "/Plugin.Activate", `null`, false},
		{"POST", "/Plugin.Activate", `{"unknown":1}`, false},
		{"POST", "/unknown", `{}`, false},
		{"POST", "/AuthZPlugin.AuthZReq", `{"User":"a","User":"b"}`, false},
		{"POST", "/AuthZPlugin.AuthZReq", `{"unknown":true}`, false},
		{"POST", "/AuthZPlugin.AuthZReq?x=1", `{}`, false},
		{"POST", "/AuthZPlugin.AuthZReq", strings.Repeat(" ", 262145), false},
	} {
		t.Run(tc.path+tc.method+tc.body[:min(len(tc.body), 40)], func(t *testing.T) {
			w := httptest.NewRecorder()
			q := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			p.Handler().ServeHTTP(w, q)
			if tc.allowed {
				if w.Body.String() != `{"Implements":["authz"]}` {
					t.Fatal(w.Body.String())
				}
			} else {
				var d Decision
				if json.Unmarshal(w.Body.Bytes(), &d) != nil || d.Allow {
					t.Fatal("malformed protocol accepted")
				}
			}
		})
	}
	b, _ := json.Marshal(r)
	w := httptest.NewRecorder()
	q := httptest.NewRequest("POST", "/AuthZPlugin.AuthZReq", bytes.NewReader(b))
	p.Handler().ServeHTTP(w, q)
	var d Decision
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	must(t, d, true)
}

func TestConfigurationAndUsedJournalCannotExpandAuthority(t *testing.T) {
	p, cfg, _ := fixture(t)
	// A concurrent plugin cannot acquire the same lifetime journal lock.
	if other, e := Open(cfg); e == nil {
		other.Close()
		t.Fatal("duplicate plugin acquired journal")
	}
	p.Close()
	for _, kind := range []string{"root-user", "unknown-tool", "mutable-image", "work-root", "journal-in-work", "missing-journal"} {
		t.Run(kind, func(t *testing.T) {
			c := cfg
			c.Images = map[string]string{"bandit": testImage}
			switch kind {
			case "root-user":
				c.UID = 0
			case "unknown-tool":
				c.Images["shell"] = testImage
			case "mutable-image":
				c.Images["bandit"] = "bandit:latest"
			case "work-root":
				c.WorkRoot = "/"
			case "journal-in-work":
				c.JournalRoot = filepath.Join(cfg.WorkRoot, "journal")
			case "missing-journal":
				c.JournalRoot = filepath.Join(filepath.Dir(cfg.JournalRoot), "missing")
			}
			if q, e := Open(c); e == nil {
				q.Close()
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
func TestStrictDecoderRejectsUnicodeAliases(t *testing.T) {
	for _, b := range []string{`{"User":"a","Uſer":"b"}`, `{"User":"a","uSER":"b"}`, `{"User":"a","\u0055ser":"b"}`, strings.Repeat("[", 18) + strings.Repeat("]", 18)} {
		var out any
		if strict([]byte(b), &out, 65536) == nil {
			t.Fatal("ambiguous or overnested JSON accepted")
		}
	}
}
