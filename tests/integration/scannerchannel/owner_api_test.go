//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/controller/internal/api"
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		req := httptest.NewRequest("GET", "http://localhost/api/v1/scans/"+job+path, nil)
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
	if _, e = f.s.DB.Exec("UPDATE sessions SET owner='owner-b' WHERE hash=?", domain.Hash([]byte(token))); e != nil {
		t.Fatal(e)
	}
	call("", 404)
	call("/result", 404)
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
