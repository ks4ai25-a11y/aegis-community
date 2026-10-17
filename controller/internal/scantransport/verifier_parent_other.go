// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package scantransport

import "errors"

func validateVerifierParent(string) error {
	return errors.New("private verifier channel unsupported on this platform")
}
