//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package enginetls

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func owned(info os.FileInfo, dir bool) bool {
	if info == nil {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && info.IsDir() == dir && (dir && info.Mode().Perm() == 0700 || !dir && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && s.Nlink == 1)
}
func readIdentity(path string) ([]byte, []byte, []byte, error) {
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path {
		return nil, nil, nil, ErrIdentity
	}
	before, e := os.Lstat(path)
	if e != nil || !owned(before, true) {
		return nil, nil, nil, ErrIdentity
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, nil, nil, ErrIdentity
	}
	defer root.Close()
	listing, e := root.Open(".")
	if e != nil {
		return nil, nil, nil, ErrIdentity
	}
	entries, e := listing.ReadDir(4)
	listing.Close()
	if e != nil && e != io.EOF || len(entries) != 3 {
		return nil, nil, nil, ErrIdentity
	}
	names := map[string]bool{"ca.pem": true, "client.pem": true, "client.key": true}
	for _, entry := range entries {
		if !names[entry.Name()] {
			return nil, nil, nil, ErrIdentity
		}
	}

	after, e := root.Stat(".")
	if e != nil || !owned(after, true) || !os.SameFile(before, after) {
		return nil, nil, nil, ErrIdentity
	}
	read := func(name string) ([]byte, error) {
		info, e := root.Lstat(name)
		if e != nil || !owned(info, false) || info.Size() < 1 || info.Size() > 16384 {
			return nil, ErrIdentity
		}
		f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return nil, ErrIdentity
		}
		defer f.Close()
		actual, e := f.Stat()
		if e != nil || !owned(actual, false) || !os.SameFile(info, actual) {
			return nil, ErrIdentity
		}
		b, e := io.ReadAll(io.LimitReader(f, 16385))
		if e != nil || len(b) > 16384 {
			return nil, ErrIdentity
		}
		return b, nil
	}
	ca, e := read("ca.pem")
	if e != nil {
		return nil, nil, nil, e
	}
	cert, e := read("client.pem")
	if e != nil {
		return nil, nil, nil, e
	}
	key, e := read("client.key")
	if e != nil {
		return nil, nil, nil, e
	}
	current, e := os.Lstat(path)
	if e != nil || !owned(current, true) || !os.SameFile(before, current) {
		return nil, nil, nil, ErrIdentity
	}
	return ca, cert, key, nil
}
