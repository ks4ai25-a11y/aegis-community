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

func workspaceBody(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, token, l, r := receiptFixture(t)
	p := scanevidence.WorkspacePlan{Tool: r.Tool, Workspace: "run-" + strings.Repeat("a", 32), Registry: source.Hash([]byte("registry")), Snapshot: r.Snapshot.Digest}
	b, e := scanevidence.EncodeWorkspaceSubmission(scanevidence.WorkspaceSubmission{Schema: "1.0", Job: l.Job.ID, Request: l.Job.RequestDigest, Token: l.Token, Plan: p})
	if e != nil {
		t.Fatal(e)
	}
	return s, token, string(b)
}

func TestWorkspaceHTTPRequiresLiveAuthorityEvenForExactReplay(t *testing.T) {
	s, token, body := workspaceBody(t)
	h := s.Handler()
	got := call(t, h, token, "workspace", body, 200)
	if got["state"] != "reserved" {
		t.Fatal(got)
	}
	replay := call(t, h, token, "workspace", body, 200)
	a := got["record"].(map[string]any)
	b := replay["record"].(map[string]any)
	if a["workspace_digest"] != b["workspace_digest"] {
		t.Fatal("live launch replay changed digest")
	}
	later := time.Now().Add(20 * time.Second)
	s.Q.Now = func() time.Time { return later }
	call(t, h, token, "workspace", body, 403)
}

func TestWorkspaceHTTPRejectsNoncanonicalNestedMetadata(t *testing.T) {
	for _, kind := range []string{"duplicate", "alias", "unknown", "null", "trailing", "path", "budget", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			s, token, body := workspaceBody(t)
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
			call(t, s.Handler(), token, "workspace", body, 400)
			var n int
			s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n)
			if n != 0 {
				t.Fatal("rejected metadata stored attempt")
			}
		})
	}
}

func TestWorkspaceHTTPAuditFailureIsFiniteAndAtomic(t *testing.T) {
	s, token, body := workspaceBody(t)
	s.Q.S.DB.Exec("CREATE TRIGGER deny_launch_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'private SQL failure'); END")
	got := call(t, s.Handler(), token, "workspace", body, 503)
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "private SQL failure") {
		t.Fatal("raw launch failure leaked")
	}
	var n int
	s.Q.S.DB.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n)
	if n != 0 {
		t.Fatal("failed audit persisted launch")
	}
}
