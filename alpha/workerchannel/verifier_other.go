// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !darwin

package workerchannel

import "errors"

func validateVerifierParent(string) error {
	return errors.New("private verifier channel unsupported on this platform")
}
