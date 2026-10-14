// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package executor

import (
	"aegis.local/source/scanevidence"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func readPinnedLockFile(path string) ([]byte, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, ErrObservation
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(absolute))
	if e != nil {
		return nil, ErrObservation
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return nil, ErrObservation
	}
	defer root.Close()
	name := filepath.Base(absolute)
	before, e := root.Lstat(name)
	if e != nil || !before.Mode().IsRegular() || before.Size() > 65536 {
		return nil, ErrObservation
	}
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrObservation
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, ErrObservation
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return nil, ErrObservation
	}
	return b, nil
}

// LoadObservationLaunch reads only a private regular metadata file. Its
// checksum detects changes, not origin or permission to release cleanup.
func LoadObservationLaunch(path string) (scanevidence.LaunchRecord, error) {
	if filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return scanevidence.LaunchRecord{}, ErrObservation
	}
	root, e := inspectionRoot(filepath.Dir(path), 0700)
	if e != nil {
		return scanevidence.LaunchRecord{}, ErrObservation
	}
	defer root.Close()
	b, e := inspectionFile(root, filepath.Base(path), 0600, 8192)
	if e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	var r scanevidence.LaunchRecord
	if inspectionJSON(b, &r, 8192) != nil {
		return r, ErrObservation
	}
	return r, nil
}

func inspectionRoot(path string, mode os.FileMode) (*os.Root, error) {
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || canonical != path {
		return nil, ErrObservation
	}
	before, e := os.Lstat(path)
	if e != nil || !before.IsDir() || before.Mode().Perm() != mode {
		return nil, ErrObservation
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, ErrObservation
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrObservation
	}
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrObservation
	}
	return root, nil
}
func inspectionChild(parent, path, prefix string) (*os.Root, error) {
	if filepath.Dir(path) != parent || !strings.HasPrefix(filepath.Base(path), prefix) || len(filepath.Base(path)) > 96 {
		return nil, ErrObservation
	}
	mode := os.FileMode(0700)
	if prefix == "aegis-source-" {
		mode = 0700
	}
	return inspectionRoot(path, mode)
}
func inspectionFile(root *os.Root, name string, mode os.FileMode, max int) ([]byte, error) {
	before, e := root.Lstat(name)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != mode || before.Size() > int64(max) {
		return nil, ErrObservation
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, ErrObservation
	}
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrObservation
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		return nil, ErrObservation
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max {
		return nil, ErrObservation
	}
	return b, nil
}
