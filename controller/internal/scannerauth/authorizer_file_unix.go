// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package scannerauth

import (
	"aegis.local/source/scanevidence"
	"os"
	"path/filepath"
	"syscall"
)

func (r *Registry) EnrollAuthorizerFile(owner, id string, minutes int, engine, registry, policy, path string) (scanevidence.AuthorizerIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || os.Geteuid() <= 0 {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	before, e := os.Lstat(parent)
	if e != nil || !before.IsDir() || before.Mode().Perm() != 0700 {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	defer root.Close()
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	name := filepath.Base(path)
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	defer f.Close()
	owned, e := f.Stat()
	if e != nil || !owned.Mode().IsRegular() {
		return scanevidence.AuthorizerIdentity{}, ErrCredential
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
		return scanevidence.AuthorizerIdentity{}, ErrCredential
	}
	out, e := r.enrollAuthorizer(owner, id, minutes, engine, registry, policy, func(token string) error {
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
		return scanevidence.AuthorizerIdentity{}, e
	}
	committed = true
	return out, nil
}
