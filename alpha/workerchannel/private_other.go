//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"fmt"
	"os"
)

func openCredential(string) (*os.File, error) {
	return nil, fmt.Errorf("private worker credential unsupported on this platform")
}
func validateSocket(string) error {
	return fmt.Errorf("private worker socket unsupported on this platform")
}
