// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrReceipt = errors.New("scanner receipt identity, coverage or privacy rejected")
var hash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var container = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)
var rule = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,160}$`)
var severity = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "informational": true}
var diagnostic = map[string]string{
	"SCAN_PARTIAL":         "Scanner reported incomplete static coverage.",
	"OUTPUT_LIMIT":         "Scanner stream exceeded its bound; no complete result.",
	"CANCELLED_OR_TIMEOUT": "Scanner was cancelled or timed out; no complete result.",
	"SCANNER_DEADLINE":     "Independent scanner guard interrupted execution; no complete result.",
	"TOOL_EXIT":            "Scanner failed or required offline data was unavailable; no complete result.",
	"INVALID_OUTPUT":       "Scanner output was invalid or unsupported; no complete result.",
}

// Expected comes only from controller-authorized job, pinned tool and map state.
// Guard/rule digest formats are checked and preserved as worker claims; this is
// not publisher signature verification or independent cleanup confirmation.
type Expected struct {
	Tools                                             []string
	App, Repository, LockDigest, Tool, Version, Image string
	Timeout                                           int
	Map                                               source.Map
	NotBefore, NotAfter                               time.Time
	// Database is the approved advisory database digest for this job. When empty,
	// no database freshness is approved and dependency results stay completed_stale_db.
	Database string
}

func bounded(s string, n int, required bool) bool {
	if len(s) > n || (required && s == "") || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func digest(v any) string { b, _ := json.Marshal(v); return source.Hash(b) }

// Normalize validates structured claims and replaces free presentation strings
// with finite messages. It clones via bounded JSON, never mutating caller data.
// It returns no partial findings on refusal and never raises evidence tiers.
func Normalize(in Execution, x Expected) (Execution, error) {
	bad := Execution{}
	b, e := json.Marshal(in)
	if e != nil || validateJSON(b) != nil {
		return bad, ErrReceipt
	}
	var r Execution
	if json.Unmarshal(b, &r) != nil {
		return bad, ErrReceipt
	}
	if x.App == "" || x.Repository == "" || !hash.MatchString(x.LockDigest) || !hash.MatchString(x.Image) || x.Version == "" || x.Timeout < 1 || x.Timeout > 120 || x.NotBefore.IsZero() || !x.NotAfter.After(x.NotBefore) {
		return bad, ErrReceipt
	}
	if len(x.Tools) < 1 || len(x.Tools) > 6 || !sort.StringsAreSorted(x.Tools) {
		return bad, ErrReceipt
	}
	selected := false
	for i, t := range x.Tools {
		if _, e := BuildInvocation(t); e != nil || i > 0 && t == x.Tools[i-1] {
			return bad, ErrReceipt
		}
		if t == x.Tool {
			selected = true
		}
	}
	if !selected {
		return bad, ErrReceipt
	}
	invocation, e := BuildInvocation(x.Tool)
	if r.Database != nil {
		invocation, e = BuildDatabaseInvocation(x.Tool)
		mountPath, pe := DatabaseContainerPath(x.Tool)
		d := r.Database
		if e != nil || pe != nil || d.ContainerPath != mountPath || !hash.MatchString(d.Digest) || !hash.MatchString(d.ManifestDigest) || d.AgeHours < 0 || d.AgeHours > 1<<20 {
			return bad, ErrReceipt
		}
		if _, te := time.Parse(time.RFC3339, d.BuiltAt); te != nil {
			return bad, ErrReceipt
		}
		if x.Database != "" && d.Digest != x.Database {
			return bad, ErrReceipt
		}
	}
	if e != nil || r.Schema != "1.0" || r.Parser != ParserVersion || r.Tool != x.Tool || r.Version != x.Version || r.Image != x.Image || r.LockDigest != x.LockDigest || r.Profile != "repo_offline-network-none-v1" || !reflect.DeepEqual(r.Invocation, invocation) {
		return bad, ErrReceipt
	}
	started, e := time.Parse(time.RFC3339Nano, r.Started)
	if e != nil || started.Before(x.NotBefore) || started.After(x.NotAfter) || started.Add(time.Duration(r.Duration)*time.Millisecond).After(x.NotAfter) || r.Duration < 0 || r.Duration > int64((x.Timeout+5)*1000) {
		return bad, ErrReceipt
	}
	m := x.Map
	claimedMap := m.Digest
	m.Digest = ""
	m.Observed = ""
	if m.Schema != "1.0" || m.App != x.App || !hash.MatchString(claimedMap) || digest(m) != claimedMap || !strings.HasPrefix(m.SourceRef, "mounted-asset:") || len(m.SourceRef) <= len("mounted-asset:") {
		return bad, ErrReceipt
	}
	s := r.Snapshot
	claimed := s.Digest
	s.Digest = ""
	if s.Schema != "1.0" || s.InputMap != claimedMap || s.Commit != m.Commit || !hash.MatchString(claimed) || digest(s) != claimed || !reflect.DeepEqual(s.Files, m.Files) || len(s.Files) > 10000 {
		return bad, ErrReceipt
	}
	paths := map[string]bool{}
	var size int64
	for _, f := range s.Files {
		if !bounded(f.Path, 512, true) || strings.Contains(f.Path, "\\") || path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || f.Path == "." || f.Path == ".." || strings.HasPrefix(f.Path, "../") || paths[f.Path] || !hash.MatchString(f.Digest) || f.Size < 0 || f.Size > source.MaxFileBytes {
			return bad, ErrReceipt
		}
		paths[f.Path] = true
		size += f.Size
	}
	if size != s.Bytes || size > source.MaxBytes {
		return bad, ErrReceipt
	}
	if r.Exit < -1 || r.Exit > 255 || r.GuardDigest != "" && !hash.MatchString(r.GuardDigest) || r.RulesDigest != "" && !hash.MatchString(r.RulesDigest) {
		return bad, ErrReceipt
	}
	if r.Cleanup != "complete" && r.Cleanup != "unconfirmed" {
		return bad, ErrReceipt
	}
	if r.Container == "" {
		if r.Status != "tool_error" || r.Exit != -1 || r.Duration != 0 || r.DurationLimit != 0 && r.DurationLimit != x.Timeout {
			return bad, ErrReceipt
		}
	} else if !container.MatchString(r.Container) || !hash.MatchString(r.GuardDigest) || r.DurationLimit != x.Timeout {
		return bad, ErrReceipt
	}
	if r.Tool == "semgrep_ce" {
		if r.Container != "" && !hash.MatchString(r.RulesDigest) {
			return bad, ErrReceipt
		}
	} else if r.RulesDigest != "" {
		return bad, ErrReceipt
	}
	if r.Result.Status != r.Status || r.Result.Findings == nil || r.Result.Diagnostics == nil || len(r.Result.Findings) > 10000 || len(r.Result.Diagnostics) > 16 {
		return bad, ErrReceipt
	}
	switch r.Status {
	case "completed", "completed_partial", "completed_stale_db":
		if r.Container == "" || r.Cleanup != "complete" {
			return bad, ErrReceipt
		}
		allowed := false
		for _, exit := range invocation.FindingExitCodes {
			if r.Exit == exit {
				allowed = true
			}
		}
		if !allowed {
			return bad, ErrReceipt
		}
	case "tool_error":
		if len(r.Result.Findings) != 0 || len(r.Result.SBOM) != 0 {
			return bad, ErrReceipt
		}
	default:
		return bad, ErrReceipt
	}
	if (r.Status == "completed" || r.Status == "completed_stale_db") && len(r.Result.Diagnostics) != 0 || r.Status == "completed_partial" && len(r.Result.Diagnostics) == 0 {
		return bad, ErrReceipt
	}
	for i, d := range r.Result.Diagnostics {
		msg, ok := diagnostic[d.Code]
		if !ok || r.Status == "completed_partial" && d.Code != "SCAN_PARTIAL" || r.Status == "tool_error" && d.Code == "SCAN_PARTIAL" {
			return bad, ErrReceipt
		}
		r.Result.Diagnostics[i].Message = msg
	}
	ids := map[string]bool{}
	for i, f := range r.Result.Findings {
		if f.Schema != "1.0" || !hash.MatchString(f.ID) || ids[f.ID] || f.App != x.App || f.Repository != x.Repository || f.Status != "suspected" || f.Tier != "T0" || f.Confidence != "low" || !severity[f.Severity] || !paths[f.Path] || f.Line < 0 || f.Line > 10000000 || len(f.Provenance) < 1 || len(f.Provenance) > 16 {
			return bad, ErrReceipt
		}
		ids[f.ID] = true
		created, e := time.Parse(time.RFC3339Nano, f.Created)
		if e != nil || created.Before(started) || created.After(x.NotAfter) {
			return bad, ErrReceipt
		}
		switch f.Category {
		case "static_pattern":
			if x.Tool != "semgrep_ce" && x.Tool != "bandit" {
				return bad, ErrReceipt
			}
		case "secret_candidate":
			if x.Tool != "gitleaks" || f.SecretFingerprint != "" && !hash.MatchString(f.SecretFingerprint) {
				return bad, ErrReceipt
			}
		case "known_vulnerable_dependency":
			if x.Tool != "osv_v2" && x.Tool != "trivy" || !bounded(f.PackageName, 256, true) || !bounded(f.Version, 128, true) || !bounded(f.Package, 1024, false) || f.Package != "" && !strings.HasPrefix(f.Package, "pkg:") || len(f.Advisories) != 1 || !rule.MatchString(f.Advisories[0]) {
				return bad, ErrReceipt
			}
		default:
			return bad, ErrReceipt // Config review requires a separately consented profile.
		}
		if f.Category != "known_vulnerable_dependency" && (f.Package != "" || f.PackageName != "" || f.Version != "" || len(f.Advisories) != 0) || f.Category != "secret_candidate" && f.SecretFingerprint != "" {
			return bad, ErrReceipt
		}
		rank := map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
		maximum := 0
		for _, p := range f.Provenance {
			if p.Tool != r.Tool || p.Version != r.Version || p.ImageDigest != r.Image || p.Parser != r.Parser || p.InputDigest != claimed || !rule.MatchString(p.Rule) || !severity[p.Severity] || p.Rule != f.Provenance[0].Rule {
				return bad, ErrReceipt
			}
		}
		for _, p := range f.Provenance {
			if rank[p.Severity] > maximum {
				maximum = rank[p.Severity]
			}
		}
		if rank[f.Severity] != maximum {
			return bad, ErrReceipt
		}
		first := f.Provenance[0]
		expected := digest([]string{x.App, x.Repository, f.Category, r.Tool, first.Rule, f.Path, fmt.Sprint(f.Line)})
		if f.Category == "known_vulnerable_dependency" {
			if f.Package != "" {
				expected = digest([]string{x.App, x.Repository, f.Category, f.Package, f.Version, f.Advisories[0], f.Path})
			} else {
				expected = digest([]string{x.App, x.Repository, f.Category, f.Advisories[0], f.Path, f.Package, f.PackageName, f.Version})
			}
			if first.Rule != f.Advisories[0] {
				return bad, ErrReceipt
			}
		}
		if f.ID != expected {
			return bad, ErrReceipt
		}
		f.Summary = "Unverified static scanner claim."
		if f.Category == "secret_candidate" {
			f.Summary = "Possible exposed credential; rotate after owner review. Matched value omitted."
		}
		f.Coverage = "Tool-reported static claim only; no application exploitability or remediation proof."
		r.Result.Findings[i] = f
	}
	if len(r.Result.SBOM) != 0 {
		if r.Tool != "syft" || r.Status != "completed" {
			return bad, ErrReceipt
		}
		sbom, e := normalizeSBOM(r.Result.SBOM)
		if e != nil {
			return bad, ErrReceipt
		}
		r.Result.SBOM = sbom
	} else if r.Tool == "syft" && r.Status == "completed" {
		return bad, ErrReceipt
	}
	if r.Status == "completed_stale_db" && r.Tool != "osv_v2" && r.Tool != "trivy" {
		return bad, ErrReceipt
	}
	// A dependency result is current only when an approved, fresh database was
	// mounted; everything else keeps completed_stale_db.
	fresh := r.Database != nil && !r.Database.Stale && x.Database != "" && r.Database.Digest == x.Database
	if (r.Tool == "osv_v2" || r.Tool == "trivy") && r.Status == "completed" && !fresh {
		r.Status = "completed_stale_db"
		r.Result.Status = r.Status
	}
	r.Limitations = []string{"Unverified static tool claims; no exploitability, remediation or complete coverage proof.", "Container, guard, rule and cleanup fields are worker claims; independent cleanup confirmation is required."}
	if (r.Tool == "osv_v2" || r.Tool == "trivy") && fresh {
		r.Limitations = append(r.Limitations, "Coverage is limited to advisories in the approved offline database built at "+r.Database.BuiltAt+"; database integrity was verified by the worker before launch.")
	} else if r.Tool == "osv_v2" || r.Tool == "trivy" {
		r.Limitations = append(r.Limitations, "Advisory database freshness is unproven; no current-vulnerability coverage claim.")
	}
	return r, nil
}
func normalizeSBOM(b []byte) (json.RawMessage, error) {
	var v struct {
		Format     string `json:"bomFormat"`
		Spec       string `json:"specVersion"`
		Version    int    `json:"version"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if validateJSON(b) != nil || canonicalKeys(b, reflect.TypeOf(v)) != nil {
		return nil, ErrReceipt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return nil, ErrReceipt
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrReceipt
	}
	if v.Format != "CycloneDX" || v.Version != 1 || v.Spec != "1.4" && v.Spec != "1.5" && v.Spec != "1.6" && v.Spec != "1.7" || v.Components == nil || len(v.Components) > 10000 {
		return nil, ErrReceipt
	}
	for _, p := range v.Components {
		if !bounded(p.Name, 256, true) || !bounded(p.Version, 128, false) || !bounded(p.PURL, 1024, false) || p.PURL != "" && !strings.HasPrefix(p.PURL, "pkg:") {
			return nil, ErrReceipt
		}
	}
	out, e := json.Marshal(v)
	return out, e
}
