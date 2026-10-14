//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/controller/internal/api"
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scanqueue"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func assertOwnerHTTPTriage(t *testing.T, f fixture, job string) {
	t.Helper()
	ctx := context.Background()
	page, e := f.q.Findings(ctx, "owner-a", job, scanqueue.FindingQuery{})
	if e != nil || len(page.Items) == 0 {
		t.Fatal(e)
	}
	record := page.Items[0].ID
	token, csrf := auth.Token(), auth.Token()
	if _, e = f.s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,strftime('%s','now'),strftime('%s','now'),strftime('%s','now')+3600)", domain.Hash([]byte(token)), "owner-a", domain.Hash([]byte(csrf))); e != nil {
		t.Fatal(e)
	}
	app := &api.Server{S: f.s, A: auth.New(f.s), Scans: f.q, Assets: t.TempDir()}
	handler := app.Handler()
	endpoint := "/api/v1/scans/" + job + "/finding-triage"
	call := func(method, path, body string, code int, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "aegis_session", Value: token})
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "http-triage-key")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != code || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	query := "?record_id=" + url.QueryEscape(record)
	initial := call("GET", endpoint+query, "", 200, nil)
	t.Logf("OWNER_HTTP_TRIAGE_INITIAL %s", initial.Body.String())
	in := scanqueue.FindingTriageInput{Schema: "1.0", Record: record, Result: page.Result, State: "false_positive", Rationale: "Reviewed <synthetic> fixture & static claim; no exploit proof"}
	b, _ := json.Marshal(in)
	body := string(b)
	call("POST", endpoint, body, 401, map[string]string{"X-CSRF-Token": ""})
	call("POST", endpoint, body, 403, map[string]string{"Origin": "https://untrusted.invalid"})
	call("POST", endpoint, "null", 400, nil)
	call("POST", endpoint, body[:len(body)-1]+",\"state\":\"accepted_risk\"}", 400, nil)
	call("POST", endpoint, body[:len(body)-1]+",\"shell\":\"unsupported\"}", 400, nil)
	call("GET", endpoint+query+"&record_id=other", "", 400, nil)
	first := call("POST", endpoint, body, 200, nil)
	var current scanqueue.FindingTriageRecord
	if json.Unmarshal(first.Body.Bytes(), &current) != nil || current.Document.Revision != 1 || current.Document.State != "false_positive" || domain.Digest(current.Document) != current.Digest {
		t.Fatal("invalid HTTP triage")
	}
	replay := call("POST", endpoint, body, 200, nil)
	if first.Body.String() != replay.Body.String() {
		t.Fatal("HTTP replay changed")
	}
	call("POST", endpoint, body, 409, map[string]string{"Idempotency-Key": "http-stale-revision"})
	latest := call("GET", endpoint+query, "", 200, nil)
	if latest.Body.String() != first.Body.String() {
		t.Fatal("latest review changed")
	}
	t.Logf("OWNER_HTTP_TRIAGE_RECORDED %s", first.Body.String())
	t.Logf("OWNER_HTTP_TRIAGE_RESULT %s", mustJSONResult(t, f, job))
	t.Logf("OWNER_HTTP_TRIAGE_PAGE %s", mustJSONPage(t, f, job))
	var raw string
	f.s.DB.QueryRow("SELECT group_concat(document) FROM audit WHERE document LIKE '%finding.triage%'").Scan(&raw)
	if strings.Contains(raw, "synthetic") || strings.Contains(raw, "static claim") {
		t.Fatal("rationale copied into audit")
	}
	if _, e = f.s.DB.Exec("UPDATE sessions SET owner='owner-b' WHERE hash=?", domain.Hash([]byte(token))); e != nil {
		t.Fatal(e)
	}
	call("GET", endpoint+query, "", 404, nil)
	call("POST", endpoint, body, 404, nil)
	assertCleanupHeld(t, f)
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func mustJSONResult(t *testing.T, f fixture, job string) string {
	t.Helper()
	r, e := f.q.Result("owner-a", job)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func mustJSONPage(t *testing.T, f fixture, job string) string {
	t.Helper()
	r, e := f.q.Findings(context.Background(), "owner-a", job, scanqueue.FindingQuery{})
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
