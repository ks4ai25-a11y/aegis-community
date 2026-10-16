//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package privateipc

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func dir(t *testing.T) string {
	t.Helper()
	p, e := os.MkdirTemp("/tmp", "apc-")
	if e != nil {
		t.Fatal(e)
	}
	p, _ = filepath.EvalSymlinks(p)
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}
func TestPrivateTokenNoOverwriteLinksAliasesOrNonprivateParent(t *testing.T) {
	p := dir(t)
	path := filepath.Join(p, "token")
	if e := EnrollToken(path); e != nil {
		t.Fatal(e)
	}
	token, e := ReadToken(path)
	if e != nil || len(token) != 64 {
		t.Fatal(e)
	}
	if EnrollToken(path) == nil {
		t.Fatal("overwritten token")
	}
	alias := filepath.Join(p, "alias")
	os.Symlink(path, alias)
	if _, e = ReadToken(alias); e == nil {
		t.Fatal("symlink token")
	}
	os.Remove(alias)
	os.Link(path, alias)
	if _, e = ReadToken(path); e == nil {
		t.Fatal("hardlink token")
	}
	os.Remove(alias)
	os.Chmod(path, 0640)
	if _, e = ReadToken(path); e == nil {
		t.Fatal("nonprivate token")
	}
	os.Chmod(path, 0600)
	os.Chmod(p, 0755)
	if _, e = ReadToken(path); e == nil {
		t.Fatal("nonprivate parent")
	}
	os.Chmod(p, 0700)
	fifo := filepath.Join(p, "fifo")
	if e = syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadToken(fifo); e == nil {
		t.Fatal("FIFO token")
	}
}
func TestPrivateListenerKeepsProcessLockWhenSocketStops(t *testing.T) {
	p := dir(t)
	path := filepath.Join(p, "s")
	l, e := Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateSocket(path); e != nil {
		t.Fatal(e)
	}
	if other, e := Listen(path); e == nil {
		other.Close()
		t.Fatal("duplicate listener")
	}
	if e = l.(interface{ CloseSocket() error }).CloseSocket(); e != nil {
		t.Fatal(e)
	}
	if other, e := Listen(path); e == nil {
		other.Close()
		t.Fatal("process lock released before shutdown")
	}
	l.Close()
	next, e := Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
	stale, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	stale.SetUnlinkOnClose(false)
	os.Chmod(path, 0600)
	stale.Close()
	next, e = Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
	occupied := filepath.Join(p, "occupied")
	os.WriteFile(occupied, []byte("retained"), 0600)
	if l, e = Listen(occupied); e == nil {
		l.Close()
		t.Fatal("ordinary file replaced")
	}
}
