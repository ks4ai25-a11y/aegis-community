// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package scannerauth

import (
	"aegis.local/source/scanevidence"
	"os"
	"path/filepath"
	"syscall"
)

func (r *Registry) EnrollVerifierFile(owner, id string, minutes int, engine, registry, path string) (scanevidence.VerifierIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || os.Geteuid() <= 0 {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	before, e := os.Lstat(parent)
	if e != nil || !before.IsDir() || before.Mode().Perm() != 0700 {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	defer root.Close()
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	name := filepath.Base(path)
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	defer f.Close()
	owned, e := f.Stat()
	if e != nil || !owned.Mode().IsRegular() {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	committed := false
	defer func() {
		if !committed {
			info, e := root.Lstat(name)
			if e == nil && os.SameFile(owned, info) {
				root.Remove(name)
			}
		}
	}()
	if e = f.Chmod(0600); e != nil {
		return scanevidence.VerifierIdentity{}, ErrCredential
	}
	out, e := r.enrollVerifier(owner, id, minutes, engine, registry, func(token string) error {
		n, e := f.WriteString(token + "\n")
		if e != nil || n != 65 {
			return ErrCredential
		}
		if e = f.Sync(); e != nil {
			return ErrCredential
		}
		info, e := root.Lstat(name)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !os.SameFile(owned, info) {
			return ErrCredential
		}
		d, e := root.Open(".")
		if e != nil {
			return ErrCredential
		}
		defer d.Close()
		return d.Sync()
	})
	if e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	committed = true
	return out, nil
}
