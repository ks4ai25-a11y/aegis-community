// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"fmt"
	"sort"
)

var severityRank = map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Dedupe preserves every supplied evidence source. It refuses an over-budget
// merge instead of silently truncating provenance or claiming zero findings.
// It only aggregates unverified static claims; proof promotion is independent.
func Dedupe(in []Finding) ([]Finding, error) {
	if len(in) > 10000 {
		return nil, fmt.Errorf("finding aggregation budget exceeded")
	}
	out := []Finding{}
	index := map[string]int{}
	for _, f := range in {
		if f.App == "" || f.Repository == "" || f.ID == "" || f.Status != "suspected" || f.Tier != "T0" || f.Confidence != "low" || len(f.Provenance) == 0 || len(f.Provenance) > 16 {
			return nil, fmt.Errorf("unsupported finding aggregation identity or proof")
		}
		if _, ok := severityRank[f.Severity]; !ok {
			return nil, fmt.Errorf("invalid claimed severity")
		}
		switch f.Category {
		case "static_pattern", "secret_candidate", "known_vulnerable_dependency", "configuration_claim":
		default:
			return nil, fmt.Errorf("unsupported finding category")
		}
		input := f.Provenance[0].InputDigest
		if input == "" {
			return nil, fmt.Errorf("finding input identity missing")
		}
		for _, s := range f.Provenance {
			if s.InputDigest != input || s.Tool == "" || s.Version == "" || s.ImageDigest == "" {
				return nil, fmt.Errorf("mixed or missing source identity")
			}
			if s.Severity != "" {
				if _, ok := severityRank[s.Severity]; !ok {
					return nil, fmt.Errorf("invalid source severity claim")
				}
				if severityRank[s.Severity] > severityRank[f.Severity] {
					f.Severity = s.Severity
				}
			}
		}
		// Source rule namespaces are tool-specific. Equal text in two unrelated
		// scanners does not establish equivalent AST/code-region observations.
		key := identityHash([]string{f.App, f.Repository, f.Category, f.ID, input})
		if f.Category == "known_vulnerable_dependency" && f.Package != "" && len(f.Advisories) == 1 {
			f.ID = identityHash([]string{f.App, f.Repository, f.Category, f.Package, f.Version, f.Advisories[0], f.Path})
			key = identityHash([]string{f.ID, input})
		} else {
			tool, rule := f.Provenance[0].Tool, f.Provenance[0].Rule
			for _, s := range f.Provenance {
				if s.Tool != tool || s.Rule != rule {
					return nil, fmt.Errorf("non-equivalent static source namespaces")
				}
			}
			key = identityHash([]string{key, tool, rule})
		}
		// Clone slices so appending a source never modifies earlier receipts.
		f.Provenance = append([]Source{}, f.Provenance...)
		f.Advisories = append([]string{}, f.Advisories...)
		if i, ok := index[key]; ok {
			target := &out[i]
			if len(target.Provenance)+len(f.Provenance) > 16 {
				return nil, fmt.Errorf("finding provenance budget exceeded")
			}
			target.Provenance = append(target.Provenance, f.Provenance...)
			if severityRank[f.Severity] > severityRank[target.Severity] {
				target.Severity = f.Severity
			}
			if f.Created < target.Created {
				target.Created = f.Created
			}
		} else {
			index[key] = len(out)
			out = append(out, f)
		}
	}
	// Stable presentation ordering; no dependency on map iteration order.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		if out[i].Repository != out[j].Repository {
			return out[i].Repository < out[j].Repository
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Provenance[0].InputDigest < out[j].Provenance[0].InputDigest
	})
	return out, nil
}
