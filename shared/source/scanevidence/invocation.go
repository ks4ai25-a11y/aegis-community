// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"fmt"
	"strings"
)

// Invocation prepares fixed argv for a separately pinned, operator-launched read-only container. It never executes repository code.
func BuildInvocation(tool string) (Invocation, error) {
	i := Invocation{Network: "none", TimeoutSeconds: 120, MaxOutput: MaxOutput, FindingExitCodes: []int{0}}
	switch tool {
	case "semgrep_ce":
		i.Args = []string{"semgrep", "scan", "--config", "/rules", "--json", "--metrics=off", "--disable-version-check", "/src"}
	case "osv_v2":
		i.Args = []string{"scan", "source", "--offline-vulnerabilities", "--no-resolve", "--format", "json", "-r", "/src"}
		i.FindingExitCodes = []int{0, 1}
	case "trivy":
		i.Args = []string{"fs", "--scanners", "vuln", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--format", "json", "/src"}
	case "syft":
		i.Args = []string{"dir:/src", "-o", "cyclonedx-json"}
	case "gitleaks":
		i.Args = []string{"dir", "/src", "--report-format", "json", "--report-path", "/dev/stdout", "--redact=100", "--exit-code", "0"}
	case "bandit":
		i.Args = []string{"--ini", "/dev/null", "--ignore-nosec", "-r", "/src", "-f", "json"}
		i.FindingExitCodes = []int{0, 1}
	default:
		return i, fmt.Errorf("scanner unsupported")
	}
	for _, v := range i.Args {
		if strings.ContainsRune(v, 0) {
			return i, fmt.Errorf("invalid argv")
		}
	}
	return i, nil
}

// DatabaseContainerPath is where an offline advisory database is mounted read-only.
func DatabaseContainerPath(tool string) (string, error) {
	switch tool {
	case "osv_v2":
		return "/db/osv", nil
	case "trivy":
		return "/db/trivy", nil
	}
	return "", fmt.Errorf("scanner uses no advisory database")
}

// BuildDatabaseInvocation is the fixed invocation when an advisory database is
// mounted. Trivy needs its cache directory in argv; OSV-Scanner reads it from
// OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, so its argv is unchanged.
func BuildDatabaseInvocation(tool string) (Invocation, error) {
	if _, e := DatabaseContainerPath(tool); e != nil {
		return Invocation{}, e
	}
	i, e := BuildInvocation(tool)
	if e != nil {
		return i, e
	}
	if tool == "trivy" {
		last := len(i.Args) - 1
		i.Args = append(append(append([]string{}, i.Args[:last]...), "--cache-dir", "/db/trivy"), i.Args[last])
	}
	return i, nil
}
