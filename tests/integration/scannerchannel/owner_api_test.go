//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scannerchannelacceptance

import (
	"aegis.local/controller/internal/api"
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Exercise the same public handler used by aegisd against real immutable
// receipts/results. Test-only sessions never grant private worker authority.
func assertOwnerHTTPResult(t *testing.T, f fixture, job string) {
	t.Helper()
	expected, e := f.q.Result("owner-a", job)
	if e != nil {
		t.Fatal(e)
	}
	token := auth.Token()
	if _, e = f.s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,strftime('%s','now'),strftime('%s','now'),strftime('%s','now')+3600)", domain.Hash([]byte(token)), "owner-a", domain.Hash([]byte("test csrf"))); e != nil {
		t.Fatal(e)
	}
	app := &api.Server{S: f.s, A: auth.New(f.s), Scans: f.q, Assets: t.TempDir()}
	h := app.Handler()
	call := func(path string, code int) *httptest.ResponseRecorder {
		t.Helper()
		target := "/scans/" + job + path
		if strings.HasPrefix(path, "/findings") {
			target = path
		}
		req := httptest.NewRequest("GET", "http://localhost/api/v1"+target, nil)
		req.AddCookie(&http.Cookie{Name: "aegis_session", Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != code || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("owner API %s: %d %s", path, w.Code, w.Body.String())
		}
		return w
	}
	w := call("/result", 200)
	var got struct {
		Digest   string             `json:"result_digest"`
		Document scanevidence.Suite `json:"document"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &got); e != nil || got.Digest != expected.Digest {
		t.Fatal("HTTP result lost identity", e)
	}
	b, e := json.Marshal(got.Document)
	if e != nil || source.Hash(b) != expected.Digest || !got.Document.CleanupRequired || got.Document.Tier != "T0" {
		t.Fatal("HTTP result weakened evidence", e)
	}
	t.Logf("OWNER_HTTP_SCAN_RESULT %s", w.Body.String())
	w = call("", 200)
	var status struct {
		Job struct {
			ID string `json:"job_id"`
		} `json:"job"`
		Admission string `json:"execution_admission"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &status); e != nil || status.Job.ID != job || status.Admission != "cleanup_required" {
		t.Fatal("terminal HTTP response lost cleanup hold", e)
	}
	t.Logf("OWNER_HTTP_SCAN_STATUS %s", w.Body.String())
	cursor := ""
	seen := map[string]bool{}
	count := 0
	for {
		w = call("/findings?job_id="+job+"&limit=2&cursor="+url.QueryEscape(cursor), 200)
		var page scanqueue.FindingPage
		if e = json.Unmarshal(w.Body.Bytes(), &page); e != nil || page.Result != expected.Digest || page.Status != expected.Document.Status || page.ToolClaims != expected.Document.FindingClaims {
			t.Fatal("findings lost result identity", e)
		}
		if len(w.Body.Bytes()) > 96<<10 {
			t.Fatal("finding response exceeded client budget")
		}
		for _, entry := range page.Items {
			if seen[entry.ID] || entry.Finding.Tier != "T0" || entry.Finding.Status != "suspected" || len(entry.Receipts) == 0 {
				t.Fatal("finding proof/receipt mismatch")
			}
			seen[entry.ID] = true
			count++
		}
		t.Logf("OWNER_HTTP_FINDINGS_PAGE %s", w.Body.String())
		if page.Next == "" {
			if count != page.Distinct {
				t.Fatal("pagination omitted findings", count, page.Distinct)
			}
			break
		}
		cursor = page.Next
	}
	call("/findings?job_id="+job+"&limit=21", 400)
	call("/findings?job_id="+job+"&job_id=other", 400)
	call("/findings?job_id="+job+"&owner_id=other", 400)

	if _, e = f.s.DB.Exec("UPDATE sessions SET owner='owner-b' WHERE hash=?", domain.Hash([]byte(token))); e != nil {
		t.Fatal(e)
	}
	call("", 404)
	call("/result", 404)
	call("/findings?job_id="+job, 404)
	assertScopedVerifierContext(t, f, job)
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
