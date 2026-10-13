// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

const ParserVersion = "1.2"

type Source struct {
	Tool        string `json:"tool_id"`
	Version     string `json:"tool_version"`
	ImageDigest string `json:"tool_image_digest"`
	Parser      string `json:"parser_version"`
	InputDigest string `json:"input_digest"`
	Rule        string `json:"rule_id,omitempty"`
	Severity    string `json:"severity_claimed,omitempty"`
}
type Finding struct {
	Schema            string   `json:"schema_version"`
	ID                string   `json:"id"`
	App               string   `json:"app_id"`
	Repository        string   `json:"repository_id"`
	Category          string   `json:"category"`
	Summary           string   `json:"summary"`
	Status            string   `json:"status"`
	Severity          string   `json:"severity"`
	Confidence        string   `json:"confidence"`
	Tier              string   `json:"evidence_tier"`
	Path              string   `json:"path,omitempty"`
	Line              int      `json:"line,omitempty"`
	Package           string   `json:"package_url,omitempty"`
	PackageName       string   `json:"package_name,omitempty"`
	Version           string   `json:"installed_version,omitempty"`
	Advisories        []string `json:"advisories,omitempty"`
	SecretFingerprint string   `json:"secret_fingerprint,omitempty"`
	Provenance        []Source `json:"provenance"`
	Coverage          string   `json:"coverage_note"`
	Created           string   `json:"created_at"`
}
type Job struct {
	App, Repository, InputDigest string
	ToolVersion, ImageDigest     string
	SecretSalt                   []byte
	ConfigReview                 bool
}
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Result struct {
	Status      string          `json:"status"`
	Findings    []Finding       `json:"findings"`
	Diagnostics []Diagnostic    `json:"diagnostics"`
	SBOM        json.RawMessage `json:"sbom,omitempty"`
}

func identityHash(parts []string) string { b, _ := json.Marshal(parts); return Hash(b) }

func Hash(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func safePath(p string) (string, error) {
	p = strings.TrimPrefix(p, "/src/")
	if !boundedCoordinate(p, 512, true) || strings.Contains(p, "\\") || strings.ContainsAny(p, "\x00\r\n\t") || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("absolute or malformed source path")
	}
	c := path.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") || c == "." || len(c) > 512 {
		return "", fmt.Errorf("source path outside repository")
	}
	return c, nil
}
func newFinding(j Job, tool, kind, rule, file string, line int, sev string) (Finding, error) {
	if len(rule) > 160 || !regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`).MatchString(rule) {
		return Finding{}, fmt.Errorf("invalid scanner rule identity")
	}
	p, e := safePath(file)
	if e != nil {
		return Finding{}, e
	}
	if line < 0 || line > 10000000 {
		return Finding{}, fmt.Errorf("invalid line")
	}
	switch sev {
	case "critical", "high", "medium", "low", "informational":
	default:
		sev = "informational"
	}
	f := Finding{Schema: "1.0", App: j.App, Repository: j.Repository, Category: kind, Summary: "Unverified " + tool + " finding: " + rule, Status: "suspected", Severity: sev, Confidence: "low", Tier: "T0", Path: p, Line: line, Provenance: []Source{{tool, j.ToolVersion, j.ImageDigest, ParserVersion, j.InputDigest, rule, sev}}, Coverage: "Tool-reported static claim only; no application exploitability or remediation proof.", Created: time.Now().UTC().Format(time.RFC3339Nano)}
	f.ID = identityHash([]string{j.App, j.Repository, kind, tool, rule, p, fmt.Sprint(line)})
	return f, nil
}
