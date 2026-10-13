// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"fmt"
	"strings"
)

type Invocation struct {
	Args             []string `json:"args"`
	Network          string   `json:"network_profile"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	MaxOutput        int      `json:"max_output_bytes"`
	FindingExitCodes []int    `json:"finding_exit_codes"`
}

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
