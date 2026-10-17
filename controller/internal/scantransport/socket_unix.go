//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type lockedListener struct {
	*net.UnixListener
	lock *os.File
	once sync.Once
}

func (l *lockedListener) Close() error {
	var e error
	l.once.Do(func() { e = l.UnixListener.Close(); l.lock.Close() })
	return e
}
func Listen(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, fmt.Errorf("invalid private worker socket path")
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return nil, fmt.Errorf("private socket parent must be canonical")
	}
	st, e := os.Lstat(parent)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("private socket directory must be owned mode 0700")
	}
	lockPath := filepath.Join(parent, ".worker-socket-lock")
	fd, e := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, fmt.Errorf("private listener lock unavailable")
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	held := false
	defer func() {
		if !held {
			lock.Close()
		}
	}()
	info, e := lock.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("invalid private listener lock")
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return nil, fmt.Errorf("private listener already held")
	}
	old, e := os.Lstat(path)
	if e == nil {
		if old.Mode()&os.ModeSocket == 0 || old.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("worker socket path occupied")
		}
		connection, probe := net.DialTimeout("unix", path, 200*time.Millisecond)
		if probe == nil {
			connection.Close()
			return nil, fmt.Errorf("worker listener already active")
		}
		if !errors.Is(probe, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("worker socket absence unconfirmed")
		}
		current, e := os.Lstat(path)
		if e != nil || !os.SameFile(old, current) {
			return nil, fmt.Errorf("worker socket identity changed")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		listener.Close()
		return nil, e
	}
	held = true
	return &lockedListener{UnixListener: listener, lock: lock}, nil
}

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
