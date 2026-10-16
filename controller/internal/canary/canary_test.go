package canary

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gateway fakes the demo gateway and, like ingest, records the WAF match event.
func gateway(t *testing.T, s *store.Store, negative int, match bool, revision func() string) *httptest.Server {
	var n atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "demo.example.test" {
			t.Error("canary left the demo host", r.Host)
		}
		id := fmt.Sprintf("0f2d3c4b-1a2b-4c3d-8e9f-%012d", n.Add(1))
		w.Header().Set("X-Aegis-Request-ID", id)
		w.Header().Set("X-Aegis-Revision", revision())
		if strings.HasPrefix(r.URL.Path, "/test-pattern") {
			if match {
				ev := domain.Event{ID: "waf-" + id, At: domain.Now(), Site: "site_demo", Request: id, Type: "waf_match", Rules: []string{"942100"}, Source: "coraza"}
				b, _ := json.Marshal(ev)
				s.DB.Exec("INSERT INTO events(id,at,request,source_key,document) VALUES(?,?,?,?,?)", ev.ID, ev.At, id, "k-"+id, string(b))
			}
			w.WriteHeader(negative)
			return
		}
		w.WriteHeader(200)
	}))
}

func setup(t *testing.T) (*store.Store, string) {
	s, e := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	_, d, _ := s.Active()
	return s, d
}

func incidents(s *store.Store) int {
	var n int
	s.DB.QueryRow("SELECT count(*) FROM incidents WHERE json_extract(notes,'$.detector_id')='DET-07'").Scan(&n)
	return n
}

func TestObserveRevisionPasses(t *testing.T) {
	s, d := setup(t)
	g := gateway(t, s, 200, true, func() string { return d })
	defer g.Close()
	marks := &Marks{}
	r := (&Canary{S: s, Gateway: g.URL, Marks: marks}).Run(context.Background())
	if r.Outcome != "PASS" || !r.Matched || incidents(s) != 0 || !marks.Has(r.RequestID) {
		t.Fatal(r)
	}
	if last, ok := Last(s); !ok || last.Outcome != "PASS" {
		t.Fatal(last)
	}
}

func TestRegressionRecordsOneUrgentIncident(t *testing.T) {
	s, d := setup(t)
	// Observe mode but the rule no longer matches: the protection regressed.
	g := gateway(t, s, 200, false, func() string { return d })
	defer g.Close()
	c := &Canary{S: s, Gateway: g.URL, Wait: 300 * time.Millisecond}
	ctx := context.Background()
	r := c.Run(ctx)
	if r.Outcome != "FAIL" || r.Incident == "" {
		t.Fatal(r)
	}
	c.Run(ctx)
	if incidents(s) != 1 {
		t.Fatal("expected one incident per revision and hour", incidents(s))
	}
	var sev string
	s.DB.QueryRow("SELECT severity FROM incidents WHERE id=?", r.Incident).Scan(&sev)
	if sev != "high" {
		t.Fatal(sev)
	}
	if e := s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}

func TestRevisionDriftFails(t *testing.T) {
	s, _ := setup(t)
	g := gateway(t, s, 200, true, func() string { return "sha256:" + strings.Repeat("0", 64) })
	defer g.Close()
	r := (&Canary{S: s, Gateway: g.URL}).Run(context.Background())
	if r.Outcome != "FAIL" || !strings.Contains(r.Detail, "different revision") {
		t.Fatal(r)
	}
}

func TestUnreachableGatewayIsInconclusiveWithoutIncident(t *testing.T) {
	s, _ := setup(t)
	r := (&Canary{S: s, Gateway: "http://127.0.0.1:1"}).Run(context.Background())
	if r.Outcome != "INCONCLUSIVE" || incidents(s) != 0 {
		t.Fatal(r)
	}
}
