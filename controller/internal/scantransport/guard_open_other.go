//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"fmt"
	"os"
)

func openGuard(*os.Root, string) (*os.File, error) {
	return nil, fmt.Errorf("packaged guards require supported Unix backend")
}
