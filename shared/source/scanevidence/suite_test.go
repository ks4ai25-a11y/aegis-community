// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"aegis.local/source"
	"testing"
)

func TestSuitePreservesMixedStatusesAndCountsToolClaims(t *testing.T) {
	tools := []SuiteTool{{Tool: "bandit", Receipt: source.Hash([]byte("a")), Status: "completed_partial", FindingClaims: 2}, {Tool: "osv_v2", Receipt: source.Hash([]byte("b")), Status: "completed_stale_db", FindingClaims: 3}, {Tool: "trivy", Receipt: source.Hash([]byte("c")), Status: "tool_error"}}
	state, count, partial, stale, failed, e := Summarize(tools)
	if e != nil || state != "tool_error" || count != 5 || !partial || !stale || !failed {
		t.Fatal(state, count, partial, stale, failed, e)
	}
	state, _, partial, stale, failed, e = Summarize(tools[:2])
	if e != nil || state != "completed_partial" || !partial || !stale || failed {
		t.Fatal(state, e)
	}
	state, _, _, stale, _, e = Summarize(tools[1:2])
	if e != nil || state != "completed_stale_db" || !stale {
		t.Fatal(state, e)
	}
}

func TestSuiteRejectsInvalidToolClaims(t *testing.T) {
	base := SuiteTool{Tool: "bandit", Receipt: source.Hash([]byte("a")), Status: "completed"}
	for _, kind := range []string{"empty", "duplicate", "unknown", "digest", "status", "count", "sbom", "error_claim"} {
		t.Run(kind, func(t *testing.T) {
			tools := []SuiteTool{base}
			switch kind {
			case "empty":
				tools = nil
			case "duplicate":
				tools = append(tools, base)
			case "unknown":
				tools[0].Tool = "shell"
			case "digest":
				tools[0].Receipt = "wrong"
			case "status":
				tools[0].Status = "secure"
			case "count":
				tools[0].FindingClaims = 10001
			case "sbom":
				tools[0].SBOM = true
			case "error_claim":
				tools[0].Status = "tool_error"
				tools[0].FindingClaims = 1
			}
			if _, _, _, _, _, e := Summarize(tools); e == nil {
				t.Fatal("invalid suite accepted")
			}
		})
	}
}
