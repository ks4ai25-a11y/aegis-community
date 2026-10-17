// SPDX-License-Identifier: BUSL-1.1
package brokerwire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDispatchOutcomesRejectAuthorityAndInvalidStateIdentity(t *testing.T) {
	base := Outcome{Schema: "1.0", State: "no_job"}
	raw, _ := json.Marshal(base)
	if _, e := Decode(raw); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"authority", "release", "hidden-job", "receipts", "unknown", "duplicate", "case", "oversized", "noncanonical", "success-no-evidence"} {
		t.Run(kind, func(t *testing.T) {
			o := base
			switch kind {
			case "authority":
				o.AllWrites = true
			case "release":
				o.Release = true
			case "hidden-job":
				o.Job = "019b827e-2fa1-7fd1-b9a2-ef8b5e2b5555"
			case "receipts":
				o.Receipts = 7
			case "success-no-evidence":
				o.State = "completed"
			}
			b, _ := json.Marshal(o)
			switch kind {
			case "unknown":
				b = []byte(strings.Replace(string(b), `{"schema_version":`, `{"extra":true,"schema_version":`, 1))
			case "duplicate":
				b = []byte(strings.Replace(string(b), `{"schema_version":`, `{"schema_version":"bad","schema_version":`, 1))
			case "case":
				b = []byte(strings.Replace(string(b), `"state":`, `"State":`, 1))
			case "oversized":
				b = []byte(strings.Repeat(" ", 4097))
			case "noncanonical":
				b = []byte(strings.Replace(string(b), `"state":`, `"state": `, 1))
			}
			if _, e := Decode(b); e == nil {
				t.Fatal("unsafe dispatch outcome", kind)
			}
		})
	}
}
