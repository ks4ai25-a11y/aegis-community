//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openCredential(path string) (*os.File, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("private credential required")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	current, e := f.Stat()
	if e != nil || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 || current.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || !os.SameFile(before, current) {
		f.Close()
		return nil, fmt.Errorf("credential identity changed")
	}
	return f, nil
}

func validateSocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return fmt.Errorf("explicit private socket required")
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return fmt.Errorf("private socket parent required")
	}
	dir, e := os.Lstat(parent)
	if e != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 || dir.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private socket parent required")
	}
	st, e := os.Lstat(path)
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("owned private socket required")
	}
	return nil
}
