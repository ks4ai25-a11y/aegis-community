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
