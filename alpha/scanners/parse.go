// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

const MaxOutput = 8 << 20

func Parse(tool string, b []byte, j Job) (Result, error) {
	bad := Result{Status: "tool_error", Findings: []Finding{}, Diagnostics: []Diagnostic{{"INVALID_OUTPUT", "Scanner output invalid or unsupported; no zero-findings claim."}}}
	if validateJSON(b) != nil {
		return bad, fmt.Errorf("invalid bounded scanner JSON")
	}
	if j.App == "" || j.Repository == "" || j.InputDigest == "" || j.ToolVersion == "" || j.ImageDigest == "" {
		return bad, fmt.Errorf("scan provenance required")
	}
	r := Result{Status: "completed", Findings: []Finding{}, Diagnostics: []Diagnostic{}}
	switch tool {
	case "semgrep_ce":
		var raw struct {
			Results *[]struct {
				Rule  string `json:"check_id"`
				Path  string `json:"path"`
				Start struct {
					Line int `json:"line"`
				} `json:"start"`
				Extra struct {
					Severity string `json:"severity"`
				} `json:"extra"`
			} `json:"results"`
			Errors []json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(b, &raw) != nil || raw.Results == nil {
			return bad, fmt.Errorf("missing Semgrep results")
		}
		if len(raw.Errors) > 0 {
			r.Status = "completed_partial"
			r.Diagnostics = append(r.Diagnostics, Diagnostic{"SCAN_PARTIAL", "Semgrep reported errors; coverage incomplete."})
		}
		for _, v := range *raw.Results {
			sev := map[string]string{"ERROR": "high", "WARNING": "medium", "INFO": "informational"}[v.Extra.Severity]
			f, e := newFinding(j, tool, "static_pattern", v.Rule, v.Path, v.Start.Line, sev)
			if e != nil {
				return bad, e
			}
			r.Findings = append(r.Findings, f)
		}
	case "gitleaks":
		var raw []struct {
			Rule   string `json:"RuleID"`
			File   string `json:"File"`
			Line   int    `json:"StartLine"`
			Secret string `json:"Secret"`
			Match  string `json:"Match"`
		}
		if json.Unmarshal(b, &raw) != nil || raw == nil {
			return bad, fmt.Errorf("invalid Gitleaks report")
		}
		if len(j.SecretSalt) < 32 {
			return bad, fmt.Errorf("secret fingerprint salt required")
		}
		for _, v := range raw {
			f, e := newFinding(j, tool, "secret_candidate", v.Rule, v.File, v.Line, "high")
			if e != nil {
				return bad, e
			}
			f.Summary = "Possible exposed credential; rotate after owner review. Matched value omitted."
			if v.Secret != "" && !strings.Contains(strings.ToUpper(v.Secret), "REDACTED") {
				f.SecretFingerprint = Hash(append(append([]byte{}, j.SecretSalt...), []byte(v.Secret)...))
			}
			r.Findings = append(r.Findings, f)
		}
	case "trivy":
		var raw struct {
			Schema  int `json:"SchemaVersion"`
			Results *[]struct {
				Target string `json:"Target"`
				Vulns  []struct {
					ID         string `json:"VulnerabilityID"`
					Pkg        string `json:"PkgName"`
					Version    string `json:"InstalledVersion"`
					Severity   string `json:"Severity"`
					Identifier struct {
						PURL string `json:"PURL"`
					} `json:"PkgIdentifier"`
				} `json:"Vulnerabilities"`
				Configs []struct {
					ID       string `json:"ID"`
					Severity string `json:"Severity"`
					Cause    struct {
						Metadata struct {
							Filename string `json:"Filename"`
							Line     int    `json:"StartLine"`
						} `json:"Metadata"`
					} `json:"CauseMetadata"`
				} `json:"Misconfigurations"`
				Secrets []json.RawMessage `json:"Secrets"`
			} `json:"Results"`
		}
		if json.Unmarshal(b, &raw) != nil || raw.Schema != 2 || raw.Results == nil {
			return bad, fmt.Errorf("unsupported Trivy schema")
		}
		for _, group := range *raw.Results {
			if len(group.Configs) > 0 && !j.ConfigReview {
				return bad, fmt.Errorf("configuration review requires explicit consent")
			}
			if len(group.Secrets) > 0 {
				return bad, fmt.Errorf("Trivy secrets require separately reviewed consent adapter")
			}
			for _, v := range group.Vulns {
				f, e := newFinding(j, tool, "known_vulnerable_dependency", v.ID, group.Target, 0, strings.ToLower(v.Severity))
				if e != nil {
					return bad, e
				}
				if e = dependencyIdentity(&f, v.Identifier.PURL, v.Pkg, v.Version, v.ID); e != nil {
					return bad, e
				}
				r.Findings = append(r.Findings, f)
			}
			for _, v := range group.Configs {
				file := v.Cause.Metadata.Filename
				if file == "" {
					file = group.Target
				}
				f, e := newFinding(j, tool, "configuration_claim", v.ID, file, v.Cause.Metadata.Line, strings.ToLower(v.Severity))
				if e != nil {
					return bad, e
				}
				r.Findings = append(r.Findings, f)
			}
		}
	case "osv_v2":
		var raw struct {
			Results *[]struct {
				Source struct {
					Path string `json:"path"`
				} `json:"source"`
				Packages []struct {
					Package struct {
						Name      string `json:"name"`
						Version   string `json:"version"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Vulns []struct {
						ID string `json:"id"`
					} `json:"vulnerabilities"`
				} `json:"packages"`
			} `json:"results"`
		}
		if json.Unmarshal(b, &raw) != nil || raw.Results == nil {
			return bad, fmt.Errorf("unsupported OSV result schema")
		}
		for _, group := range *raw.Results {
			for _, pkg := range group.Packages {
				for _, v := range pkg.Vulns {
					f, e := newFinding(j, tool, "known_vulnerable_dependency", v.ID, group.Source.Path, 0, "informational")
					if e != nil {
						return bad, e
					}
					coordinate, e := osvCoordinate(pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version)
					if e != nil {
						return bad, e
					}
					if e = dependencyIdentity(&f, coordinate, pkg.Package.Name, pkg.Package.Version, v.ID); e != nil {
						return bad, e
					}
					r.Findings = append(r.Findings, f)
				}
			}
		}
	case "syft":
		var raw struct {
			Format     string `json:"bomFormat"`
			Version    string `json:"specVersion"`
			Components *[]struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				PURL    string `json:"purl"`
			} `json:"components"`
		}
		if json.Unmarshal(b, &raw) != nil || raw.Format != "CycloneDX" || raw.Components == nil {
			return bad, fmt.Errorf("unsupported SBOM schema")
		}
		if raw.Version != "1.4" && raw.Version != "1.5" && raw.Version != "1.6" && raw.Version != "1.7" {
			return bad, fmt.Errorf("unsupported SBOM version")
		}
		if len(*raw.Components) > 10000 {
			return bad, fmt.Errorf("SBOM component cap exceeded")
		}
		for _, component := range *raw.Components {
			if len(component.Name) == 0 || len(component.Name) > 256 || len(component.Version) > 128 || len(component.PURL) > 1024 || strings.ContainsAny(component.Name+component.Version+component.PURL, "\x00\r\n") || component.PURL != "" && !strings.HasPrefix(component.PURL, "pkg:") {
				return bad, fmt.Errorf("invalid bounded package coordinate")
			}
		}
		// Export only package coordinates; never arbitrary scanner text or source snippets.
		out := map[string]any{"bomFormat": "CycloneDX", "specVersion": raw.Version, "version": 1, "components": raw.Components}
		r.SBOM, _ = json.Marshal(out)
	case "bandit":
		var raw struct {
			Results *[]struct {
				Test     string `json:"test_id"`
				File     string `json:"filename"`
				Line     int    `json:"line_number"`
				Severity string `json:"issue_severity"`
			} `json:"results"`
			Errors []json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(b, &raw) != nil || raw.Results == nil {
			return bad, fmt.Errorf("unsupported Bandit schema")
		}
		for _, v := range *raw.Results {
			f, e := newFinding(j, tool, "static_pattern", v.Test, v.File, v.Line, strings.ToLower(v.Severity))
			if e != nil {
				return bad, e
			}
			r.Findings = append(r.Findings, f)
		}
		if len(raw.Errors) > 0 {
			r.Status = "completed_partial"
			r.Diagnostics = append(r.Diagnostics, Diagnostic{"SCAN_PARTIAL", "Bandit reported parse errors; coverage incomplete."})
		}
	default:
		return bad, fmt.Errorf("unsupported scanner")
	}
	if len(r.Findings) > 10000 {
		return bad, fmt.Errorf("finding cap exceeded")
	}
	merged, e := Dedupe(r.Findings)
	if e != nil {
		return bad, e
	}
	r.Findings = merged
	return r, nil
}
