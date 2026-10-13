// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"aegis.local/source"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fixture() (Execution, Expected) {
	now := time.Now().UTC()
	m := source.Map{Schema: "1.0", App: "app_demo", SourceRef: "mounted-asset:fixture", Files: []source.File{{Path: "query.py", Digest: source.Hash([]byte("static")), Size: 6}}}
	m.Digest = digest(m)
	s := source.Manifest{Schema: "1.0", InputMap: m.Digest, Files: m.Files, Bytes: 6}
	s.Digest = digest(s)
	invocation, _ := BuildInvocation("bandit")
	x := Expected{Tools: []string{"bandit"}, App: "app_demo", Repository: "repo-a", LockDigest: source.Hash([]byte("pins")), Tool: "bandit", Version: "1.9.4", Image: source.Hash([]byte("image")), Timeout: 30, Map: m, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	f := Finding{Schema: "1.0", App: x.App, Repository: x.Repository, Category: "static_pattern", Path: "query.py", Line: 2, Status: "suspected", Tier: "T0", Confidence: "low", Severity: "medium", Created: now.Format(time.RFC3339Nano), Summary: "private arbitrary message", Coverage: "private arbitrary coverage", Provenance: []Source{{Tool: x.Tool, Version: x.Version, ImageDigest: x.Image, Parser: ParserVersion, InputDigest: s.Digest, Rule: "B307", Severity: "medium"}}}
	f.ID = digest([]string{x.App, x.Repository, f.Category, x.Tool, "B307", f.Path, "2"})
	r := Execution{Schema: "1.0", Parser: ParserVersion, Tool: x.Tool, Version: x.Version, Image: x.Image, LockDigest: x.LockDigest, Invocation: invocation, Profile: "repo_offline-network-none-v1", Snapshot: s, Started: now.Add(-time.Millisecond).Format(time.RFC3339Nano), Duration: 25, DurationLimit: 30, Exit: 1, Status: "completed", Cleanup: "complete", Container: "aegis-scan-" + strings.Repeat("a", 32), GuardDigest: source.Hash([]byte("guard")), Result: Result{Status: "completed", Findings: []Finding{f}, Diagnostics: []Diagnostic{}}, Limitations: []string{"private arbitrary limitation"}}
	return r, x
}
func TestNormalizePreservesClaimsAndReplacesFreeText(t *testing.T) {
	r, x := fixture()
	before, _ := json.Marshal(r)
	got, e := Normalize(r, x)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("caller receipt mutated")
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "private arbitrary") {
		t.Fatal("free presentation text retained")
	}
	if got.Result.Findings[0].Tier != "T0" || !reflect.DeepEqual(got.Result.Findings[0].Provenance, r.Result.Findings[0].Provenance) {
		t.Fatal("evidence source lost or promoted")
	}
	again, e := Normalize(got, x)
	if e != nil || !reflect.DeepEqual(again, got) {
		t.Fatal("normalization not idempotent")
	}
}
func TestReceiptIdentityCoverageAndProofRefusals(t *testing.T) {
	changes := map[string]func(*Execution){"pins": func(r *Execution) { r.Image = source.Hash([]byte("other")) }, "argv": func(r *Execution) { r.Invocation.Args = []string{"sh", "-c", "anything"} }, "network": func(r *Execution) { r.Invocation.Network = "host" }, "map": func(r *Execution) { r.Snapshot.InputMap = source.Hash([]byte("other")) }, "file": func(r *Execution) { r.Snapshot.Files[0].Digest = source.Hash([]byte("other")) }, "snapshot": func(r *Execution) { r.Snapshot.Digest = source.Hash([]byte("other")) }, "bytes": func(r *Execution) { r.Snapshot.Bytes++ }, "tier": func(r *Execution) { r.Result.Findings[0].Tier = "T3" }, "status": func(r *Execution) { r.Result.Findings[0].Status = "confirmed" }, "source": func(r *Execution) { r.Result.Findings[0].Provenance[0].InputDigest = source.Hash([]byte("other")) }, "namespace": func(r *Execution) { r.Result.Findings[0].Repository = "other" }, "path": func(r *Execution) { r.Result.Findings[0].Path = "../secret" }, "fingerprint": func(r *Execution) { r.Result.Findings[0].ID = source.Hash([]byte("other")) }, "parser": func(r *Execution) { r.Parser = "1.1" }, "cleanup": func(r *Execution) { r.Cleanup = "unconfirmed" }, "duration": func(r *Execution) { r.DurationLimit = 120 }, "exit": func(r *Execution) { r.Exit = 124 }, "partial": func(r *Execution) { r.Status = "completed_partial"; r.Result.Status = r.Status }, "diagnostic": func(r *Execution) { r.Result.Diagnostics = []Diagnostic{{"ARBITRARY", "raw message"}} }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r, x := fixture()
			change(&r)
			got, e := Normalize(r, x)
			if !errors.Is(e, ErrReceipt) || got.Schema != "" {
				t.Fatal("invalid receipt returned evidence")
			}
		})
	}
}
func TestPartialAndPreflightFailureRemainHonest(t *testing.T) {
	r, x := fixture()
	r.Status = "completed_partial"
	r.Result.Status = r.Status
	r.Result.Diagnostics = []Diagnostic{{"SCAN_PARTIAL", "raw tool message"}}
	got, e := Normalize(r, x)
	if e != nil || got.Status != "completed_partial" || strings.Contains(got.Result.Diagnostics[0].Message, "raw tool") {
		t.Fatal("partial claim invalid or leaked")
	}
	r, x = fixture()
	r.Status = "tool_error"
	r.Result = Result{Status: r.Status, Findings: []Finding{}, Diagnostics: []Diagnostic{}}
	r.Container = ""
	r.GuardDigest = ""
	r.Cleanup = "unconfirmed"
	r.Exit = -1
	r.Duration = 0
	r.DurationLimit = 0
	if _, e = Normalize(r, x); e != nil {
		t.Fatal("preflight error rejected", e)
	}
	r.Result.Findings = fixtureFinding()
	if _, e = Normalize(r, x); e == nil {
		t.Fatal("tool error retained findings")
	}
}
func fixtureFinding() []Finding { r, _ := fixture(); return r.Result.Findings }
func TestCanonicalDecodeRejectsHostileReceipt(t *testing.T) {
	r, _ := fixture()
	b, _ := json.Marshal(r)
	if _, e := Decode(b); e != nil {
		t.Fatal(e)
	}
	for name, body := range map[string][]byte{"duplicate": append(b[:len(b)-1], []byte(`,"schema_version":"1.0"}`)...), "alias": []byte(strings.Replace(string(b), `"tool_id":`, `"Tool_id":`, 1)), "unknown": append(b[:len(b)-1], []byte(`,"raw_output":"secret"}`)...), "trailing": append(b, []byte(`{}`)...), "null": []byte(strings.Replace(string(b), `"diagnostics":[]`, `"diagnostics":null`, 1)), "UTF8": []byte("{\"schema_version\":\"\xff\"}"), "depth": []byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66))} {
		t.Run(name, func(t *testing.T) {
			if _, e := Decode(body); !errors.Is(e, ErrReceipt) {
				t.Fatal("hostile receipt accepted")
			}
		})
	}
}
func TestSBOMProjectionAndHostileFields(t *testing.T) {
	good := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"package-a","version":"1","purl":"pkg:npm/package-a@1"}]}`)
	if _, e := normalizeSBOM(good); e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{"unknown": []byte(strings.Replace(string(good), `"name":`, `"raw_secret":"private","name":`, 1)), "alias": []byte(strings.Replace(string(good), `"name":`, `"Name":`, 1)), "duplicate": []byte(strings.Replace(string(good), `"version":1`, `"version":1,"version":1`, 1)), "null": []byte(strings.Replace(string(good), `"components":[`, `"components":null,"other":[`, 1))} {
		t.Run(name, func(t *testing.T) {
			if _, e := normalizeSBOM(b); e == nil {
				t.Fatal("hostile SBOM accepted")
			}
		})
	}
}

func TestDependencyCompletionCannotClaimFreshDatabase(t *testing.T) {
	for _, tool := range []string{"osv_v2", "trivy"} {
		t.Run(tool, func(t *testing.T) {
			r, x := fixture()
			x.Tool = tool
			x.Tools = []string{tool}
			r.Tool = tool
			r.Invocation, _ = BuildInvocation(tool)
			r.Exit = 0
			r.Result.Findings = []Finding{}
			got, e := Normalize(r, x)
			if e != nil || got.Status != "completed_stale_db" || got.Result.Status != got.Status {
				t.Fatal("unknown database freshness presented as complete current coverage")
			}
			again, e := Normalize(got, x)
			if e != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("stale database normalization not idempotent")
			}
		})
	}
	r, x := fixture()
	r.Status = "completed_stale_db"
	r.Result.Status = r.Status
	if _, e := Normalize(r, x); e == nil {
		t.Fatal("non-advisory tool accepted stale database status")
	}
}

func TestReceiptRequiresRequestedToolSelection(t *testing.T) {
	for _, tools := range [][]string{nil, {"syft"}, {"bandit", "bandit"}, {"syft", "bandit"}, {"shell"}} {
		r, x := fixture()
		x.Tools = tools
		if _, e := Normalize(r, x); e == nil {
			t.Fatal("receipt outside requested tool set accepted")
		}
	}
}
