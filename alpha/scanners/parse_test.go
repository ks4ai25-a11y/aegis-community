package scanners

import (
	"encoding/json"
	"strings"
	"testing"
)

func job() Job {
	return Job{App: "app_demo", Repository: "repo_demo", InputDigest: "sha256:input", ToolVersion: "tested-fixture", ImageDigest: "sha256:tool", SecretSalt: []byte(strings.Repeat("s", 32))}
}
func TestA012SecretBoundary(t *testing.T) {
	r, e := Parse("gitleaks", []byte(`[{"RuleID":"generic-api-key","File":"src/config.ts","StartLine":3,"Secret":"FAKE_CANARY_NOT_LIVE","Match":"password=FAKE_CANARY_NOT_LIVE"}]`), job())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "FAKE_CANARY_NOT_LIVE") {
		t.Fatal("secret escaped adapter")
	}
	if r.Findings[0].SecretFingerprint == "" {
		t.Fatal("missing secret fingerprint")
	}
}
func TestA015FailureIsNotZero(t *testing.T) {
	for _, b := range []string{`{}`, `{"results":null}`, `{corrupt}`, `{"results":[{"check_id":"unsafe","path":"../../.ssh/id_rsa"}]}`} {
		r, e := Parse("semgrep_ce", []byte(b), job())
		if e == nil || r.Status != "tool_error" {
			t.Fatal("false completed scan", r, e)
		}
	}
}
func TestA016DedupeKeepsProvenance(t *testing.T) {
	r, e := Parse("semgrep_ce", []byte(`{"results":[{"check_id":"unsafe-query","path":"src/api.ts","start":{"line":9},"extra":{"severity":"ERROR"}}]}`), job())
	if e != nil {
		t.Fatal(e)
	}
	f := r.Findings[0]
	out := Dedupe([]Finding{f, f})
	if len(out) != 1 || len(out[0].Provenance) != 2 {
		t.Fatal(out)
	}
	other := f
	other.Repository = "other"
	if len(Dedupe([]Finding{f, other})) != 2 {
		t.Fatal("cross-repository merge")
	}
}
func TestNoShellInvocation(t *testing.T) {
	for _, tool := range []string{"semgrep_ce", "osv_v2", "trivy", "syft", "gitleaks", "bandit"} {
		i, e := BuildInvocation(tool)
		if e != nil || i.Network != "none" {
			t.Fatal(tool, i, e)
		}
		for _, arg := range i.Args {
			if arg == "sh" || arg == "bash" || arg == "-c" {
				t.Fatal("shell invocation")
			}
		}
	}
}
func FuzzParser(f *testing.F) {
	f.Add([]byte(`{"results":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) { Parse("semgrep_ce", b, job()) })
}

func TestSBOMRejectsOversizedAndUnsupportedCoordinates(t *testing.T) {
	for _, report := range []string{`{"bomFormat":"CycloneDX","specVersion":"unknown","components":[]}`, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"package","version":"1","purl":"https://external.invalid"}]}`} {
		result, e := Parse("syft", []byte(report), job())
		if e == nil || result.Status != "tool_error" {
			t.Fatal("invalid SBOM accepted")
		}
	}
}
