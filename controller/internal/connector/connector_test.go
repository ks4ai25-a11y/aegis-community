// SPDX-License-Identifier: BUSL-1.1
package connector

import "testing"

func TestAllowlistIsReadOnlyAndExact(t *testing.T) {
	for _, p := range []string{"/sites", "/sites/site_shop/incidents", "/incidents/sha256:abc", "/incidents/x/proposals", "/findings/catalogue"} {
		if !Allowed("GET", p) {
			t.Error("refused", p)
		}
	}
	for _, c := range []struct{ m, p string }{{"POST", "/sites"}, {"GET", "/sites/x/policies/history"}, {"GET", "/connectors"}, {"GET", "/audit"}, {"GET", "/scans"}, {"GET", "/sites/a/b/incidents"}, {"HEAD", "/sites"}, {"GET", "/incidents/x/assessment/extra"}} {
		if Allowed(c.m, c.p) {
			t.Error("allowed", c.m, c.p)
		}
	}
}
