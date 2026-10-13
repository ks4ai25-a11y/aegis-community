//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func receiptFixture(t *testing.T) (*Server, string, scanqueue.Lease, scanevidence.Execution) {
	t.Helper()
	s, enrollment, input := fixture(t)
	_, pins, e := LoadPins("../../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	s.Q.Pins = pins
	if _, e = s.Q.Enqueue(enrollment.Worker.Owner, "receipt-http-key", input); e != nil {
		t.Fatal(e)
	}
	l, e := s.Q.Claim(enrollment.Worker.ID, enrollment.Worker.Owner)
	if e != nil {
		t.Fatal(e)
	}
	manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range manifest.Files {
		manifest.Bytes += f.Size
	}
	manifest.Digest = domain.Digest(manifest)
	inv, _ := scanevidence.BuildInvocation("bandit")
	pin := pins["bandit"]
	r := scanevidence.Execution{Schema: "1.0", Parser: scanevidence.ParserVersion, Tool: "bandit", Version: pin.Version, Image: pin.Image, LockDigest: s.Q.LockDigest, Profile: "repo_offline-network-none-v1", Invocation: inv, Snapshot: manifest, Started: time.Now().UTC().Format(time.RFC3339Nano), Exit: -1, Status: "tool_error", Cleanup: "unconfirmed", Result: scanevidence.Result{Status: "tool_error", Findings: []scanevidence.Finding{}, Diagnostics: []scanevidence.Diagnostic{}}, Limitations: []string{}}
	return s, enrollment.Token, l, r
}
func submission(t *testing.T, l scanqueue.Lease, r scanevidence.Execution) string {
	t.Helper()
	b, e := scanevidence.EncodeSubmission(scanevidence.Submission{Job: l.Job.ID, Request: l.Job.RequestDigest, Token: l.Token, Execution: r})
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func TestReceiptHTTPReplayAndExpiredNewWrite(t *testing.T) {
	s, token, l, r := receiptFixture(t)
	body := submission(t, l, r)
	h := s.Handler()
	ack := call(t, h, token, "receipt", body, 200)
	if ack["state"] != "accepted" || ack["cleanup_required"] != true {
		t.Fatal("receipt falsely completed workflow")
	}
	later := time.Now().Add(20 * time.Second)
	s.Q.Now = func() time.Time { return later }
	call(t, h, token, "receipt", body, 200)
	original, _ := time.Parse(time.RFC3339Nano, r.Started)
	r.Started = original.Add(time.Nanosecond).Format(time.RFC3339Nano)
	call(t, h, token, "receipt", submission(t, l, r), 409)
	s, token, l, r = receiptFixture(t)
	s.Q.Now = func() time.Time { return later }
	call(t, s.Handler(), token, "receipt", submission(t, l, r), 403)
}
func TestReceiptHTTPHostileBodiesAndAuthorityRefusals(t *testing.T) {
	for _, kind := range []string{"owner", "duplicate", "alias", "nested_alias", "null", "trailing", "budget", "token", "request", "cross_owner", "pin", "revoked", "cookie", "encoding"} {
		t.Run(kind, func(t *testing.T) {
			s, token, l, r := receiptFixture(t)
			body := submission(t, l, r)
			status := 400
			switch kind {
			case "owner":
				body = body[:len(body)-1] + `,"owner_id":"other"}`
			case "duplicate":
				body = body[:len(body)-1] + `,"job_id":"` + l.Job.ID + `"}`
			case "alias":
				body = strings.Replace(body, `"job_id":`, `"Job_id":`, 1)
			case "nested_alias":
				body = strings.Replace(body, `"tool_id":`, `"Tool_id":`, 1)
			case "null":
				body = strings.Replace(body, `"lease_token":"`+l.Token+`"`, `"lease_token":null`, 1)
			case "trailing":
				body += "{}"
			case "budget":
				body = strings.Repeat(" ", scanevidence.MaxSubmission+1)
			case "token":
				l.Token = strings.Repeat("a", 64)
				body = submission(t, l, r)
				status = 403
			case "request":
				l.Job.RequestDigest = domain.Hash([]byte("other"))
				body = submission(t, l, r)
				status = 409
			case "cross_owner":
				if _, e := s.Q.S.DB.Exec("UPDATE scanner_jobs SET owner='owner-b' WHERE id=?", l.Job.ID); e != nil {
					t.Fatal(e)
				}
				status = 404
			case "pin":
				r.Image = domain.Hash([]byte("other"))
				body = submission(t, l, r)
			case "revoked":
				if e := s.Auth.Revoke(l.Job.Owner, l.Worker); e != nil {
					t.Fatal(e)
				}
				status = 401
			case "cookie":
				status = 403
			}
			req := httptest.NewRequest("POST", "http://unix/internal/v1/scanner/receipt", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			if kind == "cookie" {
				req.Header.Set("Cookie", "owner=fixture")
			}
			if kind == "encoding" {
				req.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != status {
				t.Fatalf("HTTP %d; expected %d", w.Code, status)
			}
			if strings.Contains(w.Body.String(), l.Token) || strings.Contains(w.Body.String(), token) {
				t.Fatal("refusal exported capability")
			}
			var n int
			if e := s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n); e != nil || n != 0 {
				t.Fatal("refused upload persisted evidence")
			}
		})
	}
}
func TestReceiptHTTPAuditFailureIsSanitizedAndAtomic(t *testing.T) {
	s, token, l, r := receiptFixture(t)
	if _, e := s.Q.S.DB.Exec("CREATE TRIGGER receipt_http_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private database details'); END;"); e != nil {
		t.Fatal(e)
	}
	result := call(t, s.Handler(), token, "receipt", submission(t, l, r), 503)
	if result["error"].(map[string]any)["code"] != "WORKER_STATE_UNAVAILABLE" {
		t.Fatal("missing finite error")
	}
	var n int
	s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_receipts").Scan(&n)
	if n != 0 {
		t.Fatal("receipt survived failed audit")
	}
}
