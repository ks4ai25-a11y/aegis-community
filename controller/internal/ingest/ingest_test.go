// SPDX-License-Identifier: BUSL-1.1
package ingest

import (
	"aegis.local/controller/internal/canary"
	"aegis.local/controller/internal/detect"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestOversizedLineDoesNotHideNextRecord(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 1<<20)+"\n{}\n"), 8193)
	b, n, large, e := boundedLine(r)
	if e != nil || !large || n != (1<<20)+1 || len(b) != 0 {
		t.Fatalf("oversized line: %d %v %v", n, large, e)
	}
	b, n, large, e = boundedLine(r)
	if e != nil || large || string(b) != "{}\n" || n != 3 {
		t.Fatal("next record lost")
	}
}
func TestPartialRecordIsNotCommitted(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("{\"partial\":"), 8193)
	_, _, _, e := boundedLine(r)
	if e != io.EOF {
		t.Fatal(e)
	}
}
func TestTrailingJSONRejected(t *testing.T) {
	if _, e := Normalize([]byte(`{"source_schema":"caddy-2.11.4-coraza-2.6.2","source":"coraza","ts":1} {}`)); e == nil {
		t.Fatal("trailing data accepted")
	}
}
func FuzzNormalize(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 9000 {
			Normalize(b)
		}
	})
}

func TestSiteAttributionFromGatewayRequestID(t *testing.T) {
	cases := map[string]struct {
		site      string
		synthetic bool
	}{
		"0f2d3c4b-1a2b-4c3d-8e9f-001122334455":           {"site_demo", true},
		"site_shop.0f2d3c4b-1a2b-4c3d-8e9f-001122334455": {"site_shop", false},
		"site_demo.0f2d3c4b-1a2b-4c3d-8e9f-001122334455": {"site_demo", true},
		"site_SHOP.0f2d3c4b-1a2b-4c3d-8e9f-001122334455": {"site_demo", true},
		"site_shop.not-a-uuid!":                          {"site_demo", true},
		"evil site_shop.0f2d3c4b":                        {"site_demo", true},
	}
	for id, want := range cases {
		site, synthetic := SiteOf(id)
		if site != want.site || synthetic != want.synthetic {
			t.Error(id, site, synthetic)
		}
	}
}

func TestCanaryTrafficSkipsIncidentsAndDetectors(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "i.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	marks := &canary.Marks{}
	marks.Add("canary-request")
	i := &Ingestor{S: s, Detect: detect.New(detect.Defaults()), Canary: marks}
	ev := domain.Event{ID: "e1", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: "site_demo", Request: "canary-request", Type: "waf_match", Rules: []string{"942100"}, Source: "coraza"}
	if e = i.persist(ev, "k1"); e != nil {
		t.Fatal(e)
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM incidents").Scan(&n)
	var doc string
	s.DB.QueryRow("SELECT document FROM events WHERE id='e1'").Scan(&doc)
	if n != 0 || !strings.Contains(doc, `"canary":true`) {
		t.Fatal(n, doc)
	}
}

func TestSummaryRulesDoNotOpenIncidentsAndAccessRecordsJoin(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "j.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	i := &Ingestor{S: s, Detect: detect.New(detect.Defaults())}
	st := 200
	for n, ev := range []domain.Event{
		{ID: "w1", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: "site_demo", Request: "r1", Type: "waf_match", Rules: []string{"942100"}, Source: "coraza"},
		{ID: "w2", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: "site_demo", Request: "r1", Type: "waf_match", Rules: []string{"949110"}, Source: "coraza"},
		{ID: "a1", Schema: "1.0", At: "2026-10-16T12:00:00Z", Site: "site_demo", Request: "r1", Type: "access", Method: "GET", Route: "/test-pattern", Status: &st, Rules: []string{}, Source: "caddy-access", ClientKey: "aaaaaaaaaaaaaaaa"},
	} {
		if e = i.persist(ev, fmt.Sprint("k", n)); e != nil {
			t.Fatal(e)
		}
	}
	var incidents, linked int
	s.DB.QueryRow("SELECT count(*) FROM incidents").Scan(&incidents)
	s.DB.QueryRow("SELECT count(*) FROM incident_events WHERE event='a1'").Scan(&linked)
	if incidents != 1 || linked != 1 {
		t.Fatal("incidents", incidents, "access links", linked)
	}
}
