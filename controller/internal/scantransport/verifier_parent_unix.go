// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package scantransport

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateVerifierParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || os.Geteuid() <= 0 {
		return fmt.Errorf("private verifier credential path required")
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return fmt.Errorf("private verifier credential parent required")
	}
	st, e := os.Lstat(parent)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return fmt.Errorf("private verifier credential parent required")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("private verifier credential owner required")
	}
	return nil
}
