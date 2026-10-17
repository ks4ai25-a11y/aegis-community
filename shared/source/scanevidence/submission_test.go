// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSubmissionCanonicalWireAndCapabilityPrivacy(t *testing.T) {
	r, _ := fixture()
	in := Submission{Job: "019b827e-2fa1-7fd1-b9a2-ef8b5e2b5555", Request: hashFixture(), Token: strings.Repeat("a", 64), Execution: r}
	b, e := EncodeSubmission(in)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeSubmission(b)
	if e != nil || got.Token != in.Token || got.Execution.Tool != r.Tool {
		t.Fatal("private wire binding lost")
	}
	general, _ := json.Marshal(in)
	if strings.Contains(string(general), in.Token) {
		t.Fatal("general serialization leaked capability")
	}
	for name, body := range map[string][]byte{"owner": append(b[:len(b)-1], []byte(`,"owner_id":"other"}`)...), "duplicate": append(b[:len(b)-1], []byte(`,"job_id":"019b827e-2fa1-7fd1-b9a2-ef8b5e2b5555"}`)...), "alias": []byte(strings.Replace(string(b), `"job_id":`, `"Job_id":`, 1)), "nested_alias": []byte(strings.Replace(string(b), `"tool_id":`, `"Tool_id":`, 1)), "null": []byte(strings.Replace(string(b), `"lease_token":"`+in.Token+`"`, `"lease_token":null`, 1)), "trailing": append(b, []byte(`{}`)...), "budget": []byte(strings.Repeat(" ", MaxSubmission+1))} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeSubmission(body); e == nil {
				t.Fatal("hostile submission accepted")
			}
		})
	}
}
func hashFixture() string { return "sha256:" + strings.Repeat("b", 64) }
