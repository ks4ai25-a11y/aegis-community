// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

func object(fields map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": fields, "required": required, "additionalProperties": false}
}
func boundedText(limit int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": limit}
}
func boundedArray(items any, min, max int) map[string]any {
	return map[string]any{"type": "array", "items": items, "minItems": min, "maxItems": max}
}

var draftKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var draftTool = tool{
	Name:        "aegis_submit_draft_analysis",
	Description: "Return an unverified draft against a delivered incident handoff. Its owner must have enabled draft submission. Reference the supplied evidence IDs. This tool does not run the proposed steps.",
	Schema: object(map[string]any{
		"idempotency_key": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
		"incident_id":     boundedText(160),
		"handoff_id":      map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
		"client_label":    boundedText(80),
		"claims": boundedArray(object(map[string]any{
			"claim":      boundedText(500),
			"kind":       map[string]any{"enum": []string{"observation", "hypothesis"}},
			"source_ids": boundedArray(map[string]any{"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}, 1, 8),
		}, "claim", "kind", "source_ids"), 1, 10),
		"limitations": boundedArray(boundedText(320), 1, 8),
		"proposed_steps": boundedArray(object(map[string]any{
			"kind":                    map[string]any{"enum": []string{"investigation", "verification"}},
			"text":                    boundedText(400),
			"requires_owner_approval": map[string]any{"type": "boolean"},
		}, "kind", "text", "requires_owner_approval"), 0, 8),
	}, "idempotency_key", "incident_id", "handoff_id", "client_label", "claims", "limitations", "proposed_steps"),
	Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
}

func submitDraftTool(c *client, id, args json.RawMessage) map[string]any {
	var fields map[string]json.RawMessage
	var key string
	if len(args) > 32768 || json.Unmarshal(args, &fields) != nil || json.Unmarshal(fields["idempotency_key"], &key) != nil || !draftKeyPattern.MatchString(key) {
		return rpcError(id, -32602, "invalid draft arguments")
	}
	var response string
	var err error
	if c == nil {
		err = errors.New("aegis-mcp is not configured")
	} else {
		response, err = c.request(http.MethodPost, "/desktop/drafts", args, key)
	}
	if err != nil {
		return result(id, map[string]any{"isError": true, "content": []any{map[string]string{"type": "text", "text": err.Error()}}})
	}
	return result(id, map[string]any{"content": []any{map[string]string{"type": "text", "text": notice + response}}})
}
