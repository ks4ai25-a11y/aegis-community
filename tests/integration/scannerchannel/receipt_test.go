//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package scannerchannelacceptance

import (
	"aegis.local/alpha/scanners"
	"aegis.local/alpha/workerchannel"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestActualParserReceiptsShareControllerDataContract(t *testing.T) {
	f := setup(t)
	f.in.Tools = []string{"bandit", "gitleaks", "osv_v2", "semgrep_ce", "syft", "trivy"}
	enqueue(t, f)
	l, e := f.client.Claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("../../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	var lock struct {
		Tools []struct{ ID, Version, Image string }
	}
	if json.Unmarshal(b, &lock) != nil {
		t.Fatal("trusted test pin manifest invalid")
	}
	pins := map[string]struct{ Version, Image string }{}
	for _, pin := range lock.Tools {
		pins[pin.ID] = struct{ Version, Image string }{pin.Version, strings.Split(pin.Image, "@")[1]}
	}
	snapshot := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, file := range snapshot.Files {
		snapshot.Bytes += file.Size
	}
	b, _ = json.Marshal(snapshot)
	snapshot.Digest = source.Hash(b)
	inputs := map[string]string{
		"semgrep_ce": `{"results":[{"check_id":"python.eval","path":"/src/query.py","start":{"line":1},"extra":{"severity":"ERROR","message":"private arbitrary tool text"}}],"errors":[]}`,
		"bandit":     `{"results":[{"test_id":"B307","filename":"/src/query.py","line_number":1,"issue_severity":"MEDIUM","issue_text":"private arbitrary tool text"}],"errors":[]}`,
		"gitleaks":   `[{"RuleID":"fixture-secret","File":"query.py","StartLine":1,"Secret":"synthetic-only-fixture-value","Match":"synthetic-only-fixture-value"}]`,
		"osv_v2":     `{"results":[{"source":{"path":"/src/query.py"},"packages":[{"package":{"name":"fixture-package","version":"1.0","ecosystem":"npm"},"vulnerabilities":[{"id":"CVE-2026-99999"}]}]}]}`,
		"trivy":      `{"SchemaVersion":2,"Results":[{"Target":"/src/query.py","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-99999","PkgName":"fixture-package","InstalledVersion":"1.0","Severity":"HIGH","PkgIdentifier":{"PURL":"pkg:npm/fixture-package@1.0"}}]}]}`,
		"syft":       `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fixture-package","version":"1.0","purl":"pkg:npm/fixture-package@1.0"}]}`,
	}
	for tool, input := range inputs {
		t.Run(tool, func(t *testing.T) {
			started := time.Now().UTC()
			pin := pins[tool]
			parsed, e := scanners.Parse(tool, []byte(input), scanners.Job{App: l.Job.Input.App, Repository: l.Job.Input.Repository, InputDigest: snapshot.Digest, ToolVersion: pin.Version, ImageDigest: pin.Image, SecretSalt: []byte(strings.Repeat("s", 32))})
			if e != nil {
				t.Fatal("actual parser refused fixture", e)
			}
			invocation, e := scanners.BuildInvocation(tool)
			if e != nil {
				t.Fatal(e)
			}
			r := scanevidence.Execution{Schema: "1.0", Parser: scanners.ParserVersion, Tool: tool, Version: pin.Version, Image: pin.Image, LockDigest: l.Job.LockDigest, Snapshot: snapshot, Started: started.Format(time.RFC3339Nano), DurationLimit: l.Job.Input.Duration, Invocation: invocation, Profile: "repo_offline-network-none-v1", GuardDigest: source.Hash([]byte("fixture guard claim")), Status: parsed.Status, Cleanup: "complete", Container: "aegis-scan-" + source.Hash([]byte("fixture container " + tool))[7:39], Result: parsed, Limitations: []string{}}
			plan := scanevidence.LaunchPlan{Guard: r.GuardDigest, Architecture: l.Guards.Architecture(r.GuardDigest), Tool: tool, Container: r.Container, Engine: source.Hash([]byte("fixture engine")), Workspace: "run-" + source.Hash([]byte("fixture workspace " + tool))[7:39], Registry: source.Hash([]byte("fixture registry")), Snapshot: snapshot.Digest}
			if _, e = f.client.ReserveWorkspace(context.Background(), l, scanevidence.WorkspacePlan{Tool: tool, Workspace: plan.Workspace, Registry: plan.Registry, Snapshot: plan.Snapshot}); e != nil {
				t.Fatal(e)
			}
			if _, e = f.client.RegisterLaunch(context.Background(), l, plan, pin.Version, pin.Image); e != nil {
				t.Fatal("fixture launch registration refused", e)
			}
			if tool == "semgrep_ce" {
				r.RulesDigest = source.Hash([]byte("fixture rule claim"))
			}
			before, e := time.Parse(time.RFC3339Nano, l.Job.Created)
			if e != nil {
				t.Fatal(e)
			}
			expected := scanevidence.Expected{Tools: l.Job.Input.Tools, App: l.Job.Input.App, Repository: l.Job.Input.Repository, LockDigest: l.Job.LockDigest, Tool: tool, Version: pin.Version, Image: pin.Image, Timeout: l.Job.Input.Duration, Map: l.Map, NotBefore: before, NotAfter: time.Now().UTC()}
			wire, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := scanevidence.Decode(wire)
			if e != nil {
				t.Fatal("shared decode refused actual producer", e)
			}
			got, e := scanevidence.Normalize(decoded, expected)
			if e != nil {
				t.Fatal("shared validator refused actual parser", e)
			}
			if (tool == "osv_v2" || tool == "trivy") && got.Status != "completed_stale_db" {
				t.Fatal("adapter receipt claimed database freshness without evidence")
			}
			stored, e := f.client.SubmitReceipt(context.Background(), l, r)
			if e != nil || stored.State != "accepted" || !stored.Cleanup {
				t.Fatal("controller failed to ingest actual adapter fixture", e)
			}
			replay, e := f.client.SubmitReceipt(context.Background(), l, r)
			if e != nil || replay.Digest != stored.Digest {
				t.Fatal("controller receipt replay failed", e)
			}
			safe, _ := json.Marshal(stored)
			if strings.Contains(string(safe), "private arbitrary tool text") || strings.Contains(string(safe), "synthetic-only-fixture-value") {
				t.Fatal("raw scanner text escaped normalized boundary")
			}
			for _, finding := range got.Result.Findings {
				if finding.Tier != "T0" || finding.Status != "suspected" || finding.Provenance[0].InputDigest != snapshot.Digest {
					t.Fatal("claim promoted or detached from input")
				}
			}
		})
	}
	receipts, e := f.q.Receipts(l.Job.Owner, l.Job.ID)
	if e != nil || len(receipts) != 6 {
		t.Fatal("six owner-bound tool receipts not persisted", e)
	}
	job, e := f.q.Get(l.Job.Owner, l.Job.ID)
	if e != nil || job.State != "running" {
		t.Fatal("receipt ingestion fabricated suite completion")
	}
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	refs := make([]workerchannel.ReceiptAcknowledgement, 0, len(receipts))
	for _, r := range receipts {
		refs = append(refs, workerchannel.ReceiptAcknowledgement{Schema: "1.0", Job: l.Job.ID, Request: l.Job.RequestDigest, Tool: r.Document.Execution.Tool, Digest: r.Digest, State: "accepted", Cleanup: true})
	}
	finished, e := f.client.Finish(context.Background(), l, refs)
	if e != nil || finished.Document.Status != "completed_stale_db" || !finished.Document.Stale || finished.Document.ToolError || !finished.Document.CleanupRequired {
		t.Fatal("suite lost offline database uncertainty", finished, e)
	}
	if replay, e := f.client.Finish(context.Background(), l, refs); e != nil || replay.Digest != finished.Digest {
		t.Fatal("real suite replay changed result", e)
	}
	stored, e := f.q.Result(l.Job.Owner, l.Job.ID)
	if e != nil || stored.Digest != finished.Digest {
		t.Fatal("owner-bound index lost accepted receipts", e)
	}

	page, e := f.q.Findings(context.Background(), l.Job.Owner, l.Job.ID, scanqueue.FindingQuery{})
	if e != nil || page.ToolClaims != 5 || page.Distinct != 4 || !page.Stale {
		t.Fatal("cross-tool dependency aggregation failed", page, e)
	}
	merged := false
	for _, entry := range page.Items {
		if entry.Finding.Category == "known_vulnerable_dependency" {
			merged = true
			if len(entry.Finding.Provenance) != 2 || len(entry.Receipts) != 2 || entry.Finding.Severity != "high" || entry.Finding.Confidence != "low" || entry.Finding.Tier != "T0" {
				t.Fatal("dependency disagreement/proof lost", entry)
			}
		}
	}
	if !merged {
		t.Fatal("equivalent dependency sources not merged")
	}
	assertOwnerHTTPResult(t, f, l.Job.ID)
	assertCleanupHeld(t, f)
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}

}
