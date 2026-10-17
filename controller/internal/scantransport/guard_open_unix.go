//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"os"
	"syscall"
)

func openGuard(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
