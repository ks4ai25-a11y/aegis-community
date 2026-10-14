// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package scanqueue

import (
	"os"
	"syscall"
)

func privateExportParent(path string) (*os.Root, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.IsDir() || before.Mode().Perm() != 0700 || os.Geteuid() <= 0 {
		return nil, ErrInput
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, ErrInput
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrInput
	}
	return root, nil
}
