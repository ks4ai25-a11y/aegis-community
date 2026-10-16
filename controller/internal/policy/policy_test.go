package policy

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// ACME with a contact address and a rate limit must also validate offline.
	acme := sitePolicy()
	acme.Sites[0].TLS, acme.Sites[0].ACMEEmail = "acme", "ops@shop.example.com"
	acme.Sites[0].RateLimit = &domain.RateLimit{Requests: 100, WindowSeconds: 60}
	rendered = Render(acme, "demo-origin:8080", ":8080", filepath.Join(dir, "admin.sock"), filepath.Join(dir, "events.jsonl"))
	for _, want := range []string{"https://shop.example.com, https://www.shop.example.com {", " tls ops@shop.example.com", "redir @site_shop_https https://{host}{uri} 308", "events 100", "auto_https disable_redirects"} {
		if !strings.Contains(rendered, want) {
			t.Fatal("missing", want)
		}
	}
	os.WriteFile(path, []byte(rendered), 0600)
	cmd := exec.Command(bin, "validate", "--config", path, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir, "HOME="+dir)
	if out, e = cmd.CombinedOutput(); e != nil {
		t.Fatal(string(out))
	}
}

func freePort(t *testing.T) int {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestTLSAndRateLimitValidation(t *testing.T) {
	ok := sitePolicy()
	ok.Sites[0].TLS, ok.Sites[0].ACMEEmail = "acme", "ops@shop.example.com"
	ok.Sites[0].RateLimit = &domain.RateLimit{Requests: 100, WindowSeconds: 60}
	if e := Validate(ok); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*domain.SitePolicy){
		"unknown tls":        func(s *domain.SitePolicy) { s.TLS = "self" },
		"email without acme": func(s *domain.SitePolicy) { s.TLS = "internal" },
		"email injection":    func(s *domain.SitePolicy) { s.ACMEEmail = "a@b.com\n}" },
		"tiny limit":         func(s *domain.SitePolicy) { s.RateLimit = &domain.RateLimit{Requests: 1, WindowSeconds: 60} },
		"huge window":        func(s *domain.SitePolicy) { s.RateLimit = &domain.RateLimit{Requests: 100, WindowSeconds: 86400} },
	}
	for name, mutate := range cases {
		p := sitePolicy()
		p.Sites[0].TLS, p.Sites[0].ACMEEmail = "acme", "ops@shop.example.com"
		mutate(&p.Sites[0])
		if Validate(p) == nil {
			t.Error(name, "accepted")
		}
	}
	// Without TLS sites the production configuration is byte-identical to the fixture one.
	if Render(sitePolicy(), "o:1", ":8080", "/a", "/l") != RenderFixture(sitePolicy(), "o:1", ":8080", "/a", "/l") {
		t.Fatal("TLS-free render changed")
	}
}

func TestTLSRedirectAndRateLimitWithRealGateway(t *testing.T) {
	bin, _ := filepath.Abs("../../../bin/caddy")
	if out, e := exec.Command(bin, "list-modules").Output(); e != nil || !strings.Contains(string(out), "http.handlers.rate_limit") {
		t.Skip("gateway binary with rate limiting not built")
	}
	origin := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("origin ok")) })}
	ol, _ := net.Listen("tcp", "127.0.0.1:0")
	go origin.Serve(ol)
	defer origin.Close()
	dir, e := os.MkdirTemp("/tmp", "aegis-tls-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	httpPort, httpsPort := freePort(t), freePort(t)
	HTTPSPort = httpsPort
	defer func() { HTTPSPort = 8443 }()
	p := sitePolicy()
	p.Sites[0].Hostnames = []string{"shop.example.test"}
	p.Sites[0].Origin = ol.Addr().String()
	p.Sites[0].TLS = "internal"
	p.Sites[0].RateLimit = &domain.RateLimit{Requests: 10, WindowSeconds: 60}
	cfg := Render(p, "127.0.0.1:1", fmt.Sprintf(":%d", httpPort), filepath.Join(dir, "admin.sock"), filepath.Join(dir, "events.jsonl"))
	path := filepath.Join(dir, "Caddyfile")
	os.WriteFile(path, []byte(cfg), 0600)
	cmd := exec.Command(bin, "run", "--config", path, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir, "HOME="+dir)
	var logs strings.Builder
	cmd.Stderr = &logs
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	dial := func(port int) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "shop.example.test"}, DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, fmt.Sprintf("127.0.0.1:%d", port))
			}}}
	}
	var resp *http.Response
	for i := 0; i < 100; i++ {
		if resp, e = dial(httpsPort).Get("https://shop.example.test/catalog"); e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e, logs.String())
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.TLS == nil || !strings.HasPrefix(resp.Header.Get("X-Aegis-Request-ID"), "site_shop.") || resp.Header.Get("X-Aegis-Mode") != "observe" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	redirect, e := dial(httpPort).Get("http://shop.example.test/catalog")
	if e != nil {
		t.Fatal(e)
	}
	redirect.Body.Close()
	if redirect.StatusCode != 308 || !strings.HasPrefix(redirect.Header.Get("Location"), "https://shop.example.test") {
		t.Fatal("no HTTPS redirect", redirect.StatusCode, redirect.Header)
	}
	limited := 0
	for i := 0; i < 15; i++ {
		r, e := dial(httpsPort).Get("https://shop.example.test/catalog")
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode == 429 {
			limited++
		}
	}
	if limited < 5 {
		t.Fatal("rate limit not enforced", limited)
	}
	demo, e := dial(httpPort).Get("http://demo.example.test/catalog")
	if e != nil {
		t.Fatal(e)
	}
	demo.Body.Close()
	// The demo origin is unreachable here (502), but it must be routed, not redirected.
	if demo.StatusCode == 308 || demo.StatusCode == 421 || demo.Header.Get("X-Aegis-Mode") != "observe" || strings.Contains(demo.Header.Get("X-Aegis-Request-ID"), ".") {
		t.Fatal("demo HTTP listener changed", demo.StatusCode)
	}
}

func TestTrustedProxyValidation(t *testing.T) {
	p := sitePolicy()
	p.TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32", "203.0.113.0/24"}
	if e := Validate(p); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"1.0.0.0/7"}, {"10.0.0.1/8"}, {"10.0.0.0/8", "10.0.0.0/8"}, {"not-a-cidr"}, {"10.0.0.0/8\n}"}} {
		q := sitePolicy()
		q.TrustedProxies = bad
		if Validate(q) == nil {
			t.Error("accepted", bad)
		}
	}
	q := domain.Initial()
	q.Metadata.Rationale = "legacy schema"
	q.TrustedProxies = []string{"10.0.0.0/8"}
	if Validate(q) == nil {
		t.Fatal("trusted proxies accepted in schema 1.0")
	}
}

func TestRateLimitKeyFollowsTrustedProxiesOnly(t *testing.T) {
	bin, _ := filepath.Abs("../../../bin/caddy")
	if out, e := exec.Command(bin, "list-modules").Output(); e != nil || !strings.Contains(string(out), "http.handlers.rate_limit") {
		t.Skip("gateway binary with rate limiting not built")
	}
	origin := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })}
	ol, _ := net.Listen("tcp", "127.0.0.1:0")
	go origin.Serve(ol)
	defer origin.Close()
	run := func(trusted []string) func(xff string) int {
		dir, _ := os.MkdirTemp("/tmp", "aegis-proxy-")
		t.Cleanup(func() { os.RemoveAll(dir) })
		port := freePort(t)
		p := sitePolicy()
		p.Sites[0].Hostnames = []string{"shop.example.test"}
		p.Sites[0].Origin = ol.Addr().String()
		p.Sites[0].RateLimit = &domain.RateLimit{Requests: 10, WindowSeconds: 60}
		p.TrustedProxies = trusted
		path := filepath.Join(dir, "Caddyfile")
		os.WriteFile(path, []byte(Render(p, "127.0.0.1:1", fmt.Sprintf(":%d", port), filepath.Join(dir, "a.sock"), filepath.Join(dir, "e.jsonl"))), 0600)
		cmd := exec.Command(bin, "run", "--config", path, "--adapter", "caddyfile")
		cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir, "HOME="+dir)
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() })
		client := &http.Client{Timeout: 3 * time.Second}
		send := func(xff string) int {
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/catalog", port), nil)
			req.Host = "shop.example.test"
			if xff != "" {
				req.Header.Set("X-Forwarded-For", xff)
			}
			r, e := client.Do(req)
			if e != nil {
				return 0
			}
			r.Body.Close()
			return r.StatusCode
		}
		for i := 0; i < 50 && send("") == 0; i++ {
			time.Sleep(100 * time.Millisecond)
		}
		return send
	}
	count := func(send func(string) int, xff string, n int) (limited int) {
		for i := 0; i < n; i++ {
			if send(xff) == 429 {
				limited++
			}
		}
		return
	}
	// Trusted loopback proxy: each forwarded client has its own allowance.
	send := run([]string{"127.0.0.0/8"})
	if a, b := count(send, "198.51.100.1", 9), count(send, "198.51.100.2", 9); a != 0 || b != 0 {
		t.Fatal("distinct forwarded clients shared a limit", a, b)
	}
	if count(send, "198.51.100.1", 5) == 0 {
		t.Fatal("forwarded client not limited")
	}
	// No trusted proxies: a spoofed header cannot buy a fresh allowance.
	send = run(nil)
	count(send, "", 9)
	if count(send, "198.51.100.77", 5) == 0 {
		t.Fatal("untrusted X-Forwarded-For bypassed the rate limit")
	}
}

func TestGatewayAdapterClassifiesOutcomes(t *testing.T) {
	scratch, _ := os.MkdirTemp("/tmp", "aegis-adapter-")
	defer os.RemoveAll(scratch)
	socket := filepath.Join(scratch, "d.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	mode := "busy"
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			json.NewEncoder(w).Encode(map[string]string{"digest": domain.Digest(domain.Initial())})
			return
		}
		if mode == "busy" {
			w.WriteHeader(429)
		} else {
			w.WriteHeader(503)
		}
		json.NewEncoder(w).Encode(map[string]string{"error": "x"})
	})}
	go srv.Serve(ln)
	defer srv.Close()
	a := GatewayAdapter{M: &Manager{DeploySocket: socket}}
	if e = a.Apply(context.Background(), domain.Initial()); !Definitive(e) || errors.Is(e, ErrUnknownOutcome) {
		t.Fatal("busy must be definitive", e)
	}
	mode = "unknown"
	if e = a.Apply(context.Background(), domain.Initial()); Definitive(e) || !errors.Is(e, ErrUnknownOutcome) {
		t.Fatal("503 must be unknown", e)
	}
	c := a.Capabilities()
	if !c.Safety.WriteRequiresApproval || len(c.Unsupported) == 0 {
		t.Fatal(c)
	}
}
