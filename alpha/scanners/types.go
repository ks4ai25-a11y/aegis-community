// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"aegis.local/source/scanevidence"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

const ParserVersion = scanevidence.ParserVersion
const MaxOutput = scanevidence.MaxOutput

type Source = scanevidence.Source
type Finding = scanevidence.Finding

type Job struct {
	App, Repository, InputDigest string
	ToolVersion, ImageDigest     string
	SecretSalt                   []byte
	ConfigReview                 bool
}
type Diagnostic = scanevidence.Diagnostic
type Result = scanevidence.Result

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
	f := Finding{Schema: "1.0", App: j.App, Repository: j.Repository, Category: kind, Summary: "Unverified " + tool + " finding: " + rule, Status: "suspected", Severity: sev, Confidence: "low", Tier: "T0", Path: p, Line: line, Provenance: []Source{{Tool: tool, Version: j.ToolVersion, ImageDigest: j.ImageDigest, Parser: ParserVersion, InputDigest: j.InputDigest, Rule: rule, Severity: sev}}, Coverage: "Tool-reported static claim only; no application exploitability or remediation proof.", Created: time.Now().UTC().Format(time.RFC3339Nano)}
	f.ID = identityHash([]string{j.App, j.Repository, kind, tool, rule, p, fmt.Sprint(line)})
	return f, nil
}
