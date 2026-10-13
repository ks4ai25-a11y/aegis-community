// SPDX-License-Identifier: Apache-2.0
package scanevidence

import "fmt"

type SuiteTool struct {
	Tool          string `json:"tool_id"`
	Receipt       string `json:"receipt_digest"`
	Status        string `json:"status"`
	FindingClaims int    `json:"finding_claims"`
	SBOM          bool   `json:"has_sbom"`
}

// Suite indexes immutable per-tool evidence. FindingClaims is the sum of tool
// claims, never a cross-tool deduplicated vulnerability or coverage count.
type Suite struct {
	Schema          string      `json:"schema_version"`
	Owner           string      `json:"owner_id"`
	Job             string      `json:"job_id"`
	Request         string      `json:"request_digest"`
	App             string      `json:"app_id"`
	Repository      string      `json:"repository_id"`
	Map             string      `json:"map_digest"`
	Lock            string      `json:"tool_lock_digest"`
	Snapshot        string      `json:"snapshot_digest"`
	Status          string      `json:"status"`
	Tools           []SuiteTool `json:"tools"`
	FindingClaims   int         `json:"finding_claims"`
	Partial         bool        `json:"has_partial"`
	Stale           bool        `json:"has_stale_database"`
	ToolError       bool        `json:"has_tool_error"`
	Tier            string      `json:"evidence_tier"`
	CleanupRequired bool        `json:"cleanup_required"`
	Created         string      `json:"created_at"`
}

// Summarize conservatively preserves independent incomplete/stale/error flags.
// It validates a sorted, unique set and never converts an error to clean output.
func Summarize(tools []SuiteTool) (status string, claims int, partial, stale, toolError bool, err error) {
	if len(tools) < 1 || len(tools) > 6 {
		err = fmt.Errorf("invalid suite tool set")
		return
	}
	for i, t := range tools {
		_, e := BuildInvocation(t.Tool)
		if e != nil || !hash.MatchString(t.Receipt) || i > 0 && tools[i-1].Tool >= t.Tool || t.FindingClaims < 0 || t.FindingClaims > 10000 || t.SBOM && t.Tool != "syft" {
			err = fmt.Errorf("invalid suite tool claim")
			return
		}
		switch t.Status {
		case "completed":
		case "completed_partial":
			partial = true
		case "completed_stale_db":
			stale = true
		case "tool_error":
			toolError = true
			if t.FindingClaims != 0 || t.SBOM {
				err = fmt.Errorf("invalid failed tool claim")
				return
			}
		default:
			err = fmt.Errorf("invalid suite tool status")
			return
		}
		claims += t.FindingClaims
	}
	status = "completed"
	if stale {
		status = "completed_stale_db"
	}
	if partial {
		status = "completed_partial"
	}
	if toolError {
		status = "tool_error"
	}
	return
}
