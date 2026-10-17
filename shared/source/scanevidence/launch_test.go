// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLaunchEnvelopeUsesCanonicalKeysAndHidesGeneralCapability(t *testing.T) {
	in := LaunchSubmission{Schema: "1.0", Job: "job", Request: "request", Token: "private-capability", Plan: LaunchPlan{Tool: "bandit", Container: "container", Engine: "engine", Workspace: "workspace", Registry: "registry", Snapshot: "snapshot"}}
	b, e := EncodeLaunchSubmission(in)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeLaunchSubmission(b)
	if e != nil || got != in {
		t.Fatal(got, e)
	}
	general, _ := json.Marshal(in)
	if strings.Contains(string(general), in.Token) {
		t.Fatal("general envelope serialization exposed capability")
	}
	for _, bad := range []string{strings.Replace(string(b), `"tool_id"`, `"Tool_ID"`, 1), strings.Replace(string(b), `"tool_id":"bandit"`, `"tool_id":"bandit","tool_id":"bandit"`, 1), strings.Replace(string(b), `"plan":{`, `"plan":{"unknown":true,`, 1), strings.Replace(string(b), `"engine_digest":"engine"`, `"engine_digest":null`, 1), string(b) + `{}`, strings.Repeat(" ", 8193)} {
		if _, e := DecodeLaunchSubmission([]byte(bad)); e == nil {
			t.Fatal("noncanonical launch envelope accepted")
		}
	}
}
