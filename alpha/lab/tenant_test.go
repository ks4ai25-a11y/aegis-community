// SPDX-License-Identifier: BUSL-1.1
package lab

import "testing"

func TestTenantClosedLoop(t *testing.T) {
	for _, v := range []string{"vulnerable", "wrong_owner_fix", "deny_all"} {
		r, e := VerifyTenant(v)
		if e != nil {
			t.Fatal(e)
		}
		if r.Overall == "PASS" {
			t.Fatal("false green", v)
		}
	}
	r, e := VerifyTenant("owner_fix")
	if e != nil || r.Overall != "PASS" || !r.BaselineReproduced || len(r.Checks) != 6 {
		t.Fatal(r, e)
	}
	// Selecting a compiled variant is not a tested mitigation or code fix.
	if r.Tier != "T2" || r.CandidateApplied {
		t.Fatal("tier overclaim", r.Tier, r.CandidateApplied)
	}
}
func TestUnknownPatchCannotExecute(t *testing.T) {
	if _, e := VerifyTenant("sh -c unsafe"); e == nil {
		t.Fatal("unknown fixture accepted")
	}
}
