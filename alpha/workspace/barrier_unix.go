//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workspace

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// registryLease is private: callbacks cannot drop the barrier before their
// synchronous controller operation completes. It never represents authority.
type registryLease struct {
	root               *os.Root
	lock               *os.File
	path               string
	rootInfo, lockInfo os.FileInfo
	namespace          string
	namespaceInfo      os.FileInfo
}

func privateEntry(info os.FileInfo, mode os.FileMode) bool {
	if info == nil || info.Mode() != mode {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && (info.IsDir() || st.Nlink == 1)
}

func openRegistry(path string, create bool) (*registryLease, error) {
	if os.Geteuid() <= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("canonical non-root workspace registry required")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil || parent != filepath.Dir(path) {
		return nil, fmt.Errorf("canonical workspace registry parent required")
	}
	if !trustedRegistryParent(parent) {
		return nil, fmt.Errorf("workspace registry parent permits replacement")
	}
	if create {
		if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return nil, e
		}
	}
	before, e := os.Lstat(path)
	if e != nil || !privateEntry(before, os.ModeDir|0700) {
		return nil, fmt.Errorf("private registry unavailable")
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	valid := false
	defer func() {
		if !valid {
			root.Close()
		}
	}()
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("registry identity changed")
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags = os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	}
	f, e := root.OpenFile(".registry-lock", flags, 0600)
	if e != nil {
		return nil, e
	}
	held := false
	defer func() {
		if !held {
			f.Close()
		}
	}()
	info, e := f.Stat()
	if e != nil || !privateEntry(info, 0600) || info.Size() != 0 {
		return nil, fmt.Errorf("invalid registry lock")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return nil, fmt.Errorf("workspace registry busy")
	}
	l := &registryLease{root: root, lock: f, path: path, rootInfo: before, lockInfo: info}
	l.namespace, l.namespaceInfo, e = l.readNamespace()
	if e != nil {
		return nil, e
	}
	if e = l.check(); e != nil {
		return nil, e
	}
	valid, held = true, true
	return l, nil
}

func trustedRegistryParent(path string) bool {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (int(st.Uid) == os.Geteuid() || st.Uid == 0) && (info.Mode().Perm()&0022 == 0 || info.Mode()&os.ModeSticky != 0)
}

func (l *registryLease) check() error {
	info, e := os.Lstat(l.path)
	if e != nil || !privateEntry(info, os.ModeDir|0700) || !os.SameFile(info, l.rootInfo) {
		return fmt.Errorf("registry identity changed")
	}
	canonical, e := filepath.EvalSymlinks(l.path)
	if e != nil || canonical != l.path {
		return fmt.Errorf("registry path changed")
	}
	info, e = l.root.Lstat(".registry-lock")
	if e != nil || !privateEntry(info, 0600) || info.Size() != 0 || !os.SameFile(info, l.lockInfo) {
		return fmt.Errorf("registry lock identity changed")
	}
	namespace, namespaceInfo, e := l.readNamespace()
	if e != nil || namespace != l.namespace || (l.namespaceInfo != nil && (namespaceInfo == nil || !os.SameFile(namespaceInfo, l.namespaceInfo))) {
		return fmt.Errorf("registry namespace changed")
	}
	return nil
}

func (l *registryLease) Close() error {
	e := l.lock.Close()
	if r := l.root.Close(); e == nil {
		e = r
	}
	return e
}

func (l *registryLease) sync() error {
	f, e := l.root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func (l *registryLease) empty() error {
	if e := l.check(); e != nil {
		return e
	}
	f, e := l.root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	entries, e := f.ReadDir(3)
	if e != nil && e != io.EOF {
		return e
	}
	for _, entry := range entries {
		if entry.Name() != ".registry-lock" && !(entry.Name() == registryNamespaceFile && l.namespace != "") {
			return ErrOccupied
		}
	}
	return nil
}

// InitializeRegistry provisions a new empty namespace only. Existing or partial
// state is never repaired/replaced. Errors retain the new namespace for review.
func InitializeRegistry(ctx context.Context, path string) error {
	_, e := InitializeRegistryNamespace(ctx, path)
	return e
}

func InitializeRegistryNamespace(ctx context.Context, path string) (namespace string, err error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if os.Geteuid() <= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("canonical non-root registry required")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil || parent != filepath.Dir(path) {
		return "", fmt.Errorf("canonical registry parent required")
	}
	if !trustedRegistryParent(parent) {
		return "", fmt.Errorf("workspace registry parent permits replacement")
	}
	if e = os.Mkdir(path, 0700); e != nil {
		return "", fmt.Errorf("new absent registry required")
	}
	l, e := openRegistry(path, true)
	if e != nil {
		return "", e
	}
	defer func() {
		if e := l.Close(); err == nil {
			err = e
		}
	}()
	if e = l.initializeNamespace(); e != nil {
		return "", e
	}
	if e = l.empty(); e != nil {
		return "", e
	}
	if e = l.lock.Sync(); e != nil {
		return "", e
	}
	if e = l.sync(); e != nil {
		return "", e
	}
	p, e := os.Open(parent)
	if e != nil {
		return "", e
	}
	e = p.Sync()
	if closeErr := p.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return "", e
	}
	if e = l.check(); e != nil {
		return "", e
	}
	return l.namespace, ctx.Err()
}

// WithEmptyRegistry holds an existing, read-only-opened registry lock across a
// synchronous callback. Missing locks/unknown entries/active creation refuse.
// No file is created, deleted or repaired. A successful callback is NOT proof
// of engine absence, legacy lease exclusion, or permission to release a slot.
func WithEmptyRegistry(ctx context.Context, path string, work func() error) (err error) {
	return withEmptyRegistry(ctx, path, "", work)
}

// WithBoundEmptyRegistry additionally requires the namespace digest previously
// approved by the operator/controller, never one inferred from current absence.
func WithBoundEmptyRegistry(ctx context.Context, path, namespace string, work func() error) error {
	if !engineDigest.MatchString(namespace) {
		return fmt.Errorf("approved registry namespace required")
	}
	return withEmptyRegistry(ctx, path, namespace, work)
}

func withEmptyRegistry(ctx context.Context, path, namespace string, work func() error) (err error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if work == nil {
		return fmt.Errorf("synchronous registry callback required")
	}
	l, e := openRegistry(path, false)
	if e != nil {
		return e
	}
	defer func() {
		if e := l.Close(); err == nil {
			err = e
		}
	}()
	if namespace != "" && namespace != l.namespace {
		return fmt.Errorf("approved registry namespace mismatch")
	}
	if e = l.empty(); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e = work(); e != nil {
		return e
	}
	if e = l.empty(); e != nil {
		return e
	}
	return ctx.Err()
}

// RegistryNamespace reads existing protocol2 identity without creating or
// repairing state. Occupied workspaces are not proof of emptiness or cleanup.
func RegistryNamespace(ctx context.Context, path string) (namespace string, err error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	l, e := openRegistry(path, false)
	if e != nil {
		return "", e
	}
	defer func() {
		if e := l.Close(); err == nil {
			err = e
		}
	}()
	if l.namespace == "" {
		return "", fmt.Errorf("provisioned registry namespace required")
	}
	if e = l.check(); e != nil {
		return "", e
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return l.namespace, nil
}
