//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func launchBody(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, token, l, r := receiptFixture(t)
	p := scanevidence.LaunchPlan{Tool: r.Tool, Container: "aegis-scan-" + strings.Repeat("a", 32), Engine: source.Hash([]byte("engine")), Workspace: "run-" + strings.Repeat("a", 32), Registry: source.Hash([]byte("registry")), Snapshot: r.Snapshot.Digest}
	if _, e := s.Q.ReserveWorkspace(l, scanevidence.WorkspacePlan{Tool: p.Tool, Workspace: p.Workspace, Registry: p.Registry, Snapshot: p.Snapshot}); e != nil {
		t.Fatal(e)
	}
	b, e := scanevidence.EncodeLaunchSubmission(scanevidence.LaunchSubmission{Schema: "1.0", Job: l.Job.ID, Request: l.Job.RequestDigest, Token: l.Token, Plan: p})
	if e != nil {
		t.Fatal(e)
	}
	return s, token, string(b)
}

func TestLaunchHTTPRequiresLiveAuthorityEvenForExactReplay(t *testing.T) {
	s, token, body := launchBody(t)
	h := s.Handler()
	got := call(t, h, token, "launch", body, 200)
	if got["state"] != "authorized" {
		t.Fatal(got)
	}
	replay := call(t, h, token, "launch", body, 200)
	a := got["record"].(map[string]any)
	b := replay["record"].(map[string]any)
	if a["launch_digest"] != b["launch_digest"] {
		t.Fatal("live launch replay changed digest")
	}
	later := time.Now().Add(20 * time.Second)
	s.Q.Now = func() time.Time { return later }
	call(t, h, token, "launch", body, 403)
}

func TestLaunchHTTPRejectsNoncanonicalNestedMetadata(t *testing.T) {
	for _, kind := range []string{"duplicate", "alias", "unknown", "null", "trailing", "path", "budget", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			s, token, body := launchBody(t)
			switch kind {
			case "duplicate":
				body = strings.Replace(body, `"tool_id":"bandit"`, `"tool_id":"bandit","tool_id":"bandit"`, 1)
			case "alias":
				body = strings.Replace(body, `"tool_id"`, `"Tool_ID"`, 1)
			case "unknown":
				body = strings.Replace(body, `"plan":{`, `"plan":{"unknown":true,`, 1)
			case "null":
				body = strings.Replace(body, `"tool_id":"bandit"`, `"tool_id":null`, 1)
			case "trailing":
				body += "{}"
			case "path":
				body = strings.Replace(body, `"workspace_id":"run-`+strings.Repeat("a", 32)+`"`, `"workspace_id":"../../private"`, 1)
			case "budget":
				body = strings.Repeat(" ", 8193)
			case "cleanup":
				body = strings.TrimSuffix(body, "}") + `,"cleanup_confirmed":true}`
			}
			call(t, s.Handler(), token, "launch", body, 400)
			var n int
			s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
			if n != 0 {
				t.Fatal("rejected metadata stored attempt")
			}
		})
	}
}

func TestLaunchHTTPAuditFailureIsFiniteAndAtomic(t *testing.T) {
	s, token, body := launchBody(t)
	s.Q.S.DB.Exec("CREATE TRIGGER deny_launch_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private SQL failure'); END")
	got := call(t, s.Handler(), token, "launch", body, 503)
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "private SQL failure") {
		t.Fatal("raw launch failure leaked")
	}
	var n int
	s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n)
	if n != 0 {
		t.Fatal("failed audit persisted launch")
	}
}
