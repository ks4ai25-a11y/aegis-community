//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package recovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func owned(info os.FileInfo, mode os.FileMode, dir bool) bool {
	if info == nil || info.IsDir() != dir || info.Mode().Perm() != mode {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid() && (dir || info.Mode().IsRegular() && s.Nlink == 1)
}

type private struct {
	root *os.Root
	lock *os.File
	path string
}

func (p *private) close() {
	if p.lock != nil {
		p.lock.Close()
	}
	p.root.Close()
}
func openPrivate(path string, create bool) (*private, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrRecovery
	}
	canonical, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil || canonical != filepath.Dir(path) {
		return nil, ErrRecovery
	}
	parent, e := os.Lstat(canonical)
	if e != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return nil, ErrRecovery
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, ErrRecovery
	}
	if create {
		if e = os.Mkdir(path, 0700); e != nil {
			return nil, ErrRecovery
		}
	}
	before, e := os.Lstat(path)
	if e != nil || !owned(before, 0700, true) {
		return nil, ErrRecovery
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrRecovery
	}
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) || !owned(after, 0700, true) {
		root.Close()
		return nil, ErrRecovery
	}
	p := &private{root: root, path: path}
	success := false
	defer func() {
		if !success {
			p.close()
		}
	}()
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	prior, e := root.Lstat(".lock")
	if !create && (e != nil || !owned(prior, 0600, false) || prior.Size() != 0) {
		return nil, ErrRecovery
	}
	f, e := root.OpenFile(".lock", flags, 0600)
	if e != nil {
		return nil, ErrRecovery
	}
	p.lock = f
	info, e := f.Stat()
	current, ce := root.Lstat(".lock")
	if e != nil || ce != nil || !owned(info, 0600, false) || !owned(current, 0600, false) || info.Size() != 0 || !os.SameFile(info, current) || prior != nil && !os.SameFile(prior, info) || syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrRecovery
	}
	success = true
	return p, nil
}
func (p *private) sync() error {
	f, e := p.root.Open(".")
	if e != nil {
		return ErrRecovery
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrRecovery
	}
	return nil
}
func (p *private) write(name string, data []byte) error {
	f, e := p.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return ErrRecovery
	}
	defer f.Close()
	n, e := f.Write(data)
	if e != nil || n != len(data) || f.Sync() != nil || f.Close() != nil {
		return ErrRecovery
	}
	return p.sync()
}
func readOwned(ctx context.Context, path string, max int64, privateOnly bool) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Size() > max || before.Mode().Perm()&0022 != 0 {
		return nil, ErrRecovery
	}
	s, ok := before.Sys().(*syscall.Stat_t)
	if !ok || s.Nlink != 1 || (int(s.Uid) != os.Geteuid() && s.Uid != 0) || privateOnly && !owned(before, 0600, false) {
		return nil, ErrRecovery
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrRecovery
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return nil, ErrRecovery
	}
	if ctx.Err() != nil {
		return nil, ErrRecovery
	}
	data, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(data)) > max || ctx.Err() != nil {
		return nil, ErrRecovery
	}
	final, e := f.Stat()
	if e != nil || final.Size() != before.Size() || !final.ModTime().Equal(before.ModTime()) {
		return nil, ErrRecovery
	}
	return data, nil
}
func hashOrCopy(ctx context.Context, p *private, name string, out *private, target string, max int64) (Artifact, error) {
	var a Artifact
	before, e := p.root.Lstat(name)
	if e != nil || !owned(before, 0600, false) || before.Size() > max {
		return a, ErrRecovery
	}
	f, e := p.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return a, ErrRecovery
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(before, actual) || !owned(actual, 0600, false) {
		return a, ErrRecovery
	}
	var dest *os.File
	if out != nil {
		dest, e = out.root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if e != nil {
			return a, ErrRecovery
		}
		defer dest.Close()
	}
	h := sha256.New()
	buf := make([]byte, 32768)
	var size int64
	for {
		if ctx.Err() != nil {
			return a, ErrRecovery
		}
		n, re := f.Read(buf)
		size += int64(n)
		if size > max {
			return a, ErrRecovery
		}
		h.Write(buf[:n])
		if dest != nil {
			w, we := dest.Write(buf[:n])
			if we != nil || w != n {
				return a, ErrRecovery
			}
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			return a, ErrRecovery
		}
	}
	after, e := f.Stat()
	current, ce := p.root.Lstat(name)
	if e != nil || ce != nil || !owned(current, 0600, false) || !os.SameFile(before, current) || !os.SameFile(before, after) || size != before.Size() || !before.ModTime().Equal(after.ModTime()) {
		return a, ErrRecovery
	}
	if dest != nil {
		if dest.Sync() != nil || dest.Close() != nil {
			return a, ErrRecovery
		}
		if out.sync() != nil {
			return a, ErrRecovery
		}
	}
	return Artifact{Bytes: size, Digest: fmt.Sprintf("sha256:%x", h.Sum(nil))}, nil
}
