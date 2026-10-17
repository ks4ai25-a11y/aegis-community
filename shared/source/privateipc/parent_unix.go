//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package privateipc

import (
	"os"
	"path/filepath"
	"syscall"
)

func validateParent(parent string) error {
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent || !filepath.IsAbs(parent) {
		return ErrPrivate
	}
	st, e := os.Lstat(parent)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return ErrPrivate
	}
	return nil
}
