// SPDX-License-Identifier: BUSL-1.1
//go:build aegisfault

package engineauthz

import "os"

// Test-only fault injection for the hosted crash-repair acceptance (ADR 057).
// Only a binary built with -tags aegisfault contains this file; release
// builds never do. The process exits right after the controller committed a
// create admission and before any Allow reply, as a killed authorizer would.
func init() {
	if os.Getenv("AEGIS_AUTHZ_FAULT") == "exit-after-create-admission" {
		faultAfterCreateAdmission = func() { os.Exit(86) }
	}
}
