// SPDX-License-Identifier: BUSL-1.1
package scanners

import (
	"encoding/json"
	"strings"
	"testing"
)

func dependencyClaim(t *testing.T, tool, severity string) Finding {
	t.Helper()
	f, e := newFinding(job(), tool, "known_vulnerable_dependency", "CVE-2026-1234", "package-lock.json", 0, severity)
	if e != nil {
		t.Fatal(e)
	}
	if e = dependencyIdentity(&f, "pkg:npm/example@1.0", "example", "1.0", "CVE-2026-1234"); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestMergePreservesSourceSeverityWithoutProofPromotion(t *testing.T) {
	a := dependencyClaim(t, "trivy", "high")
	b := dependencyClaim(t, "osv_v2", "informational")
	out, e := Dedupe([]Finding{a, b})
	if e != nil || len(out) != 1 {
		t.Fatal(out, e)
	}
	if out[0].Severity != "high" || out[0].Tier != "T0" || out[0].Status != "suspected" || out[0].Confidence != "low" {
		t.Fatal("static claims promoted", out)
	}
	claims := map[string]string{}
	for _, p := range out[0].Provenance {
		claims[p.Tool] = p.Severity
	}
	if claims["trivy"] != "high" || claims["osv_v2"] != "informational" {
		t.Fatal("source disagreement lost", claims)
	}
	reverse, e := Dedupe([]Finding{b, a})
	if e != nil || reverse[0].ID != out[0].ID {
		t.Fatal("order changed dependency identity", e)
	}
}
func TestMergeDoesNotMutateEarlierEvidence(t *testing.T) {
	a := dependencyClaim(t, "trivy", "high")
	a.Provenance = append(make([]Source, 0, 4), a.Provenance...)
	before, _ := json.Marshal(a)
	b := dependencyClaim(t, "osv_v2", "informational")
	out, e := Dedupe([]Finding{a, b})
	if e != nil {
		t.Fatal(e)
	}
	out[0].Provenance[0].Rule = "changed-output"
	after, _ := json.Marshal(a)
	if string(before) != string(after) || a.Provenance[:cap(a.Provenance)][1].Tool != "" {
		t.Fatal("source receipt modified during aggregation")
	}
}
func TestMergeSeparatesSnapshotsAndStaticNamespaces(t *testing.T) {
	a := dependencyClaim(t, "trivy", "high")
	b := a
	b.Provenance = append([]Source{}, a.Provenance...)
	b.Provenance[0].InputDigest = Hash([]byte("different-source-snapshot"))
	out, e := Dedupe([]Finding{a, b})
	if e != nil || len(out) != 2 {
		t.Fatal("different snapshots merged", out, e)
	}
	x, e := newFinding(job(), "semgrep_ce", "static_pattern", "same-rule", "query.py", 1, "high")
	if e != nil {
		t.Fatal(e)
	}
	y, e := newFinding(job(), "bandit", "static_pattern", "same-rule", "query.py", 1, "high")
	if e != nil {
		t.Fatal(e)
	}
	out, e = Dedupe([]Finding{x, y})
	if e != nil || len(out) != 2 || out[0].ID == out[1].ID {
		t.Fatal("unrelated static namespaces merged", out, e)
	}
}
func TestMergeProvenanceCapNeverDropsEvidenceSilently(t *testing.T) {
	f := dependencyClaim(t, "trivy", "high")
	sixteen := make([]Finding, 16)
	for i := range sixteen {
		sixteen[i] = f
	}
	out, e := Dedupe(sixteen)
	if e != nil || len(out) != 1 || len(out[0].Provenance) != 16 {
		t.Fatal(out, e)
	}
	out, e = Dedupe(append(sixteen, f))
	if e == nil || out != nil {
		t.Fatal("over-budget merge silently accepted", e)
	}
	row := `{"check_id":"same-rule","path":"query.py","start":{"line":1},"extra":{"severity":"WARNING"}}`
	raw := `{"results":[` + strings.TrimSuffix(strings.Repeat(row+",", 17), ",") + `]}`
	r, e := Parse("semgrep_ce", []byte(raw), job())
	if e == nil || r.Status != "tool_error" || len(r.Findings) != 0 {
		t.Fatal("overflow became completed zero findings", r, e)
	}
}
func TestMergeRejectsProofOrMixedSourceIdentity(t *testing.T) {
	for _, kind := range []string{"proof", "mixed-input", "source-severity"} {
		f := dependencyClaim(t, "trivy", "high")
		switch kind {
		case "proof":
			f.Tier = "T5"
		case "mixed-input":
			f.Provenance = append(f.Provenance, f.Provenance[0])
			f.Provenance[1].InputDigest = "different"
		case "source-severity":
			f.Provenance[0].Severity = "fake-critical-score"
		}
		if _, e := Dedupe([]Finding{f}); e == nil {
			t.Fatal("unsupported aggregation accepted", kind)
		}
	}
}
