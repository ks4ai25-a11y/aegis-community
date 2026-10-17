// SPDX-License-Identifier: BUSL-1.1
//go:build !aegisfault

package engineauthz

import "testing"

// Release builds carry no crash fault injection, whatever the environment.
func TestReleaseBuildHasNoFaultInjection(t *testing.T) {
	if faultAfterCreateAdmission != nil {
		t.Fatal("fault injection compiled into a release build")
	}
}
