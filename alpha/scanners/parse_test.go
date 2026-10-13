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
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, tool := range []string{"semgrep_ce", "gitleaks", "osv_v2", "trivy", "syft", "bandit"} {
			Parse(tool, b, job())
		}
	})
}

func TestSBOMRejectsOversizedAndUnsupportedCoordinates(t *testing.T) {
	for _, report := range []string{`{"bomFormat":"CycloneDX","specVersion":"unknown","components":[]}`, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"package","version":"1","purl":"https://external.invalid"}]}`} {
		result, e := Parse("syft", []byte(report), job())
		if e == nil || result.Status != "tool_error" {
			t.Fatal("invalid SBOM accepted")
		}
	}
}

func TestHostileJSONNeverBecomesCleanCompletion(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(`{"results":[],"results":[]}`),
		[]byte(`{"results":[],"RESULTS":[]}`),
		[]byte(`{"results":[],"\u0072esults":[]}`),
		[]byte(`{"results":[],"unknown":{"id":1,"ID":2}}`),
		append([]byte(`{"results":[],"metadata":"`), append([]byte{0xff}, []byte(`"}`)...)...),
		[]byte(`{"results":[]} {"results":[]}`),
		[]byte(`{"results":[],"metadata":` + strings.Repeat("[", 66) + `0` + strings.Repeat("]", 66) + `}`),
		[]byte(`{"results":[],"metadata":[` + strings.Repeat("0,", 10000) + `0]}`),
	} {
		r, e := Parse("semgrep_ce", input, job())
		if e == nil || r.Status != "tool_error" || len(r.Findings) != 0 {
			t.Fatal("hostile JSON completed", r, e)
		}
	}
	for _, input := range []string{`{"SchemaVersion":2}`, `{"SchemaVersion":2,"Results":null}`} {
		r, e := Parse("trivy", []byte(input), job())
		if e == nil || r.Status != "tool_error" {
			t.Fatal("missing results completed", r, e)
		}
	}
}
func TestDependencyIdentityKeepsSeparatePackagesVersionsAndOwners(t *testing.T) {
	report := `{"SchemaVersion":2,"Results":[{"Target":"package-lock.json","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2026-1234","PkgName":"first","InstalledVersion":"1","Severity":"HIGH","PkgIdentifier":{"PURL":"pkg:npm/first@1"}},
 {"VulnerabilityID":"CVE-2026-1234","PkgName":"first","InstalledVersion":"2","Severity":"HIGH","PkgIdentifier":{"PURL":"pkg:npm/first@2"}},
 {"VulnerabilityID":"CVE-2026-1234","PkgName":"second","InstalledVersion":"1","Severity":"HIGH"}]}]}`
	r, e := Parse("trivy", []byte(report), job())
	if e != nil {
		t.Fatal(e)
	}
	ids := map[string]bool{}
	for _, f := range r.Findings {
		if ids[f.ID] {
			t.Fatal("distinct packages/versions share identity")
		}
		ids[f.ID] = true
		if f.PackageName == "" {
			t.Fatal("missing declared package identity")
		}
	}
	if len(Dedupe(r.Findings)) != 3 {
		t.Fatal("separate packages merged")
	}
	for _, field := range []string{"App", "Repository", "Path"} {
		f := r.Findings[0]
		switch field {
		case "App":
			f.App = "other"
		case "Repository":
			f.Repository = "other"
		case "Path":
			f.Path = "other-lock.json"
		}
		if len(Dedupe([]Finding{r.Findings[0], f})) != 2 {
			t.Fatal("scope/location merged", field)
		}
	}
}
func TestDependencyMalformedCoordinatesAndFakeScores(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("p", 257), "package\nprivate", "package\u202ehidden"} {
		report := map[string]any{"SchemaVersion": 2, "Results": []any{map[string]any{"Target": "package-lock.json", "Vulnerabilities": []any{map[string]any{"VulnerabilityID": "CVE-2026-1234", "PkgName": name, "InstalledVersion": "1", "Severity": "HIGH"}}}}}
		b, _ := json.Marshal(report)
		r, e := Parse("trivy", b, job())
		if e == nil || r.Status != "tool_error" {
			t.Fatal("invalid package accepted", name)
		}
	}
	report := `{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"@scope/pkg","version":"1.2.3","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-aaaa-bbbb-cccc","severity":[{"type":"CVSS_V3","score":"99999"}],"database_specific":{"severity":"CRITICAL"},"details":"FAKE_PRIVATE_CANARY"}]}]}]}`
	r, e := Parse("osv_v2", []byte(report), job())
	if e != nil {
		t.Fatal(e)
	}
	f := r.Findings[0]
	if f.Package != "pkg:npm/%40scope/pkg@1.2.3" || f.Severity != "informational" || f.Tier != "T0" {
		t.Fatal("forged score trusted or wrong coordinate", f)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "FAKE_PRIVATE_CANARY") {
		t.Fatal("arbitrary advisory details escaped")
	}
}
func TestGitleaksWhitespaceAndRedactedSecret(t *testing.T) {
	r, e := Parse("gitleaks", []byte(" \n "+`[{"RuleID":"generic-api-key","File":"config.ts","StartLine":1,"Secret":"REDACTED","Match":"FAKE_PRIVATE_CANARY"}]`), job())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "FAKE_PRIVATE_CANARY") || r.Findings[0].SecretFingerprint != "" {
		t.Fatal("redacted secret fingerprint fabricated")
	}
}

func TestConfigurationFindingsRequireSeparateConsent(t *testing.T) {
	report := []byte(`{"SchemaVersion":2,"Results":[{"Target":"Dockerfile","Misconfigurations":[{"ID":"AVD-TEST-0001","Severity":"HIGH","CauseMetadata":{"Metadata":{"Filename":"Dockerfile","StartLine":1}}}]}]}`)
	r, e := Parse("trivy", report, job())
	if e == nil || r.Status != "tool_error" {
		t.Fatal("configuration review implicitly enabled")
	}
	consent := job()
	consent.ConfigReview = true
	r, e = Parse("trivy", report, consent)
	if e != nil || len(r.Findings) != 1 {
		t.Fatal(r, e)
	}
}
