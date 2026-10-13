//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinishHTTPDerivesResultAndReplaysAfterExpiry(t *testing.T) {
	s, token, l, r := receiptFixture(t)
	body := map[string]string{"job_id": l.Job.ID, "request_digest": l.Job.RequestDigest, "lease_token": l.Token}
	b, _ := json.Marshal(body)
	h := s.Handler()
	call(t, h, token, "finish", string(b), 409)
	call(t, h, token, "receipt", submission(t, l, r), 200)
	ack := call(t, h, token, "finish", string(b), 200)
	doc := ack["document"].(map[string]any)
	if doc["status"] != "tool_error" || doc["cleanup_required"] != true || doc["evidence_tier"] != "T0" {
		t.Fatal(ack)
	}
	later := time.Now().Add(time.Minute)
	s.Q.Now = func() time.Time { return later }
	replay := call(t, h, token, "finish", string(b), 200)
	if replay["result_digest"] != ack["result_digest"] {
		t.Fatal("finish replay changed digest")
	}
	call(t, h, token, "guard", string(b), 403)
	call(t, h, token, "finish", strings.TrimSuffix(string(b), "}")+`,"cleanup_confirmed":true}`, 400)
}

func TestFinishHTTPAuditFailureIsFiniteAndAtomic(t *testing.T) {
	s, token, l, r := receiptFixture(t)
	h := s.Handler()
	call(t, h, token, "receipt", submission(t, l, r), 200)
	if _, e := s.Q.S.DB.Exec("CREATE TRIGGER refuse_finish BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private database diagnostic'); END"); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"job_id": l.Job.ID, "request_digest": l.Job.RequestDigest, "lease_token": l.Token})
	got := call(t, h, token, "finish", string(b), 503)
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "private database diagnostic") || strings.Contains(string(encoded), l.Token) {
		t.Fatal("private finalization failure leaked")
	}
	j, e := s.Q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || j.State != "running" {
		t.Fatal("failed finish changed job", j, e)
	}
}
