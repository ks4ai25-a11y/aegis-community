package policy

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPO001ObserveDefault(t *testing.T) {
	p := domain.Initial()
	if Validate(p) != nil || p.Mode != "observe" {
		t.Fatal(p)
	}
	rendered := Render(p, "demo-origin:8080", ":8080", "/run/gateway.sock", "/tmp/events")
	if !strings.Contains(rendered, "SecRuleEngine DetectionOnly") {
		t.Fatal("initial policy can block")
	}
}
func TestPO003InjectionRejected(t *testing.T) {
	p := domain.Initial()
	p.Exclusions = []domain.Exclusion{{RuleID: 942100, Method: "GET", Path: "/catalog", Parameter: "foo\nSecRuleEngine Off"}}
	if Validate(p) == nil {
		t.Fatal("directive injection accepted")
	}
	p.Exclusions[0].Parameter = "safe"
	p.Exclusions[0].Path = "/"
	if Validate(p) == nil {
		t.Fatal("broad exclusion accepted")
	}
}
func TestCanonicalRenderer(t *testing.T) {
	p := domain.Initial()
	a := Render(p, "demo-origin:8080", ":8080", "/run/gateway.sock", "/tmp/events")
	b := Render(p, "demo-origin:8080", ":8080", "/run/gateway.sock", "/tmp/events")
	if a != b {
		t.Fatal("nondeterministic config")
	}
}

func TestRemoteTypedContract(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "deployer.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Policy   domain.Policy `json:"policy"`
			Expected string        `json:"expected_revision"`
		}
		if auth.Decode(r, &in) != nil {
			w.WriteHeader(400)
			return
		}
		if r.URL.Path == "/apply" && in.Expected != domain.Digest(domain.Initial()) {
			t.Error("missing compare-and-swap revision")
		}
		json.NewEncoder(w).Encode(map[string]string{"digest": domain.Digest(domain.Initial())})
	})
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()
	m := Manager{DeploySocket: socket}
	if _, e = m.Remote(context.Background(), "apply", domain.Initial()); e != nil {
		t.Fatal(e)
	}
}

func TestApprovedCrashReconciliation(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	_, old, e := s.Active()
	if e != nil {
		t.Fatal(e)
	}
	p := domain.Initial()
	p.Parent = old
	p.Mode = "protect"
	p.Metadata.Rationale = "Durably approved Protect fixture"
	d := domain.Digest(p)
	b, _ := json.Marshal(p)
	if _, e = s.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", d, old, string(b), "APPLYING", domain.Now(), "owner"); e != nil {
		t.Fatal(e)
	}
	if e = s.Set("apply_journal", d); e != nil {
		t.Fatal(e)
	}
	scratch, e := os.MkdirTemp("/tmp", "aegis-policy-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(scratch)
	socket := filepath.Join(scratch, "helper.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Error("already-confirmed policy must not reload")
		}
		json.NewEncoder(w).Encode(map[string]string{"digest": d})
	})}
	go srv.Serve(ln)
	defer srv.Close()
	m := Manager{S: s, DeploySocket: socket}
	if e = m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	_, got, e := s.Active()
	if e != nil || got != d {
		t.Fatal(got, e)
	}
	if e = s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	// A crash after DB commit but before journal cleanup is also recoverable.
	s.Set("apply_journal", d)
	if e = m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestBusyDeployerDoesNotFreeze(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	_, old, e := s.Active()
	if e != nil {
		t.Fatal(e)
	}
	p := domain.Initial()
	p.Parent = old
	p.Mode = "protect"
	p.Metadata.Rationale = "Busy deployer fixture"
	d := domain.Digest(p)
	b, _ := json.Marshal(p)
	if _, e = s.DB.Exec("INSERT INTO policies VALUES(?,?,?,?,?,?)", d, old, string(b), "PENDING_APPROVAL", domain.Now(), "owner"); e != nil {
		t.Fatal(e)
	}
	scratch, e := os.MkdirTemp("/tmp", "aegis-policy-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(scratch)
	socket := filepath.Join(scratch, "helper.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(map[string]string{"digest": old})
		case "/validate":
			json.NewEncoder(w).Encode(map[string]string{"digest": d})
		default:
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "deployment operation in progress"})
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	m := Manager{S: s, DeploySocket: socket}
	if e = m.Apply(context.Background(), p, "owner"); !errors.Is(e, ErrDeployerBusy) {
		t.Fatal("busy deployer must be reported definitively:", e)
	}
	if m.Frozen.Load() {
		t.Fatal("definitive busy response froze policy changes")
	}
	var state string
	if e = s.DB.QueryRow("SELECT state FROM policies WHERE digest=?", d).Scan(&state); e != nil || state != "PENDING_APPROVAL" {
		t.Fatal(state, e)
	}
	if journal, _ := s.Get("apply_journal"); journal != "" {
		t.Fatal("journal left behind", journal)
	}
}

func sitePolicy() domain.Policy {
	p := domain.Initial()
	p.Schema = "1.1"
	p.Metadata.Rationale = "Register the shop application"
	p.Sites = []domain.SitePolicy{{ID: "site_shop", Name: "Shop", Hostnames: []string{"shop.example.com", "www.shop.example.com"}, Origin: "shop-app:3000", Mode: "observe", CRS: domain.CRS{Blocking: 1, Executing: 2, Threshold: 5}, Exclusions: []domain.Exclusion{{RuleID: 942100, Method: "POST", Path: "/api/search", Parameter: "q"}}}}
	return p
}

func TestLegacyDigestUnchanged(t *testing.T) {
	// Schema 1.0 documents must serialise exactly as before registered sites existed.
	b, _ := json.Marshal(domain.Initial())
	if strings.Contains(string(b), "sites") {
		t.Fatal("legacy policy gained a sites field:", string(b))
	}
}

func TestSiteValidation(t *testing.T) {
	if e := Validate(sitePolicy()); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*domain.Policy){
		"schema 1.0 with sites":   func(p *domain.Policy) { p.Schema = "1.0" },
		"demo id":                 func(p *domain.Policy) { p.Sites[0].ID = "site_demo" },
		"claims demo host":        func(p *domain.Policy) { p.Sites[0].Hostnames = []string{"demo.example.test"} },
		"bare host":               func(p *domain.Policy) { p.Sites[0].Hostnames = []string{"shop"} },
		"wildcard host":           func(p *domain.Policy) { p.Sites[0].Hostnames = []string{"*.example.com"} },
		"loopback origin":         func(p *domain.Policy) { p.Sites[0].Origin = "127.0.0.1:3000" },
		"metadata origin":         func(p *domain.Policy) { p.Sites[0].Origin = "169.254.169.254:80" },
		"controller origin":       func(p *domain.Policy) { p.Sites[0].Origin = "controller:7410" },
		"origin with path":        func(p *domain.Policy) { p.Sites[0].Origin = "shop-app:3000/x" },
		"origin injection":        func(p *domain.Policy) { p.Sites[0].Origin = "shop-app:3000\n}" },
		"blocking rule exclusion": func(p *domain.Policy) { p.Sites[0].Exclusions[0].RuleID = 949110 },
		"root exclusion":          func(p *domain.Policy) { p.Sites[0].Exclusions[0].Path = "/" },
		"regex exclusion":         func(p *domain.Policy) { p.Sites[0].Exclusions[0].Path = "/api/.*" },
		"name injection":          func(p *domain.Policy) { p.Sites[0].Name = "x`\nSecRuleEngine Off" },
		"duplicate host": func(p *domain.Policy) {
			s := p.Sites[0]
			s.ID = "site_other"
			s.Exclusions = nil
			p.Sites = append(p.Sites, s)
		},
	}
	for name, mutate := range cases {
		p := sitePolicy()
		mutate(&p)
		if Validate(p) == nil {
			t.Error(name, "accepted")
		}
	}
}

func TestProtectRequiresObservedSite(t *testing.T) {
	parent := domain.Initial()
	candidate := sitePolicy()
	candidate.Sites[0].Mode = "protect"
	if ProtectRequiresObservation(parent, candidate) == nil {
		t.Fatal("protect allowed on a never-observed site")
	}
	if ProtectRequiresObservation(sitePolicy(), candidate) != nil {
		t.Fatal("protect refused after observation")
	}
}

func TestRenderedSitesValidateWithGateway(t *testing.T) {
	bin, e := filepath.Abs("../../../bin/caddy")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(bin); e != nil {
		t.Skip("gateway binary not built")
	}
	dir := t.TempDir()
	rendered := Render(sitePolicy(), "demo-origin:8080", ":8080", filepath.Join(dir, "admin.sock"), filepath.Join(dir, "events.jsonl"))
	for _, want := range []string{"@site_shop host shop.example.com www.shop.example.com", "reverse_proxy shop-app:3000", "X-Aegis-Request-ID site_shop.{http.request.uuid}", "@owned host localhost 127.0.0.1 demo.example.test"} {
		if !strings.Contains(rendered, want) {
			t.Fatal("missing", want)
		}
	}
	path := filepath.Join(dir, "Caddyfile")
	os.WriteFile(path, []byte(rendered), 0600)
	out, e := exec.Command(bin, "validate", "--config", path, "--adapter", "caddyfile").CombinedOutput()
	if e != nil {
		t.Fatal(string(out))
	}
}
