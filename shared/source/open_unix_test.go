// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package source

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRegularFileReplacedByFIFOIsRejectedWithoutBlocking(t *testing.T) {
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(path, "source"), []byte("ordinary"), 0600)
	root, e := os.OpenRoot(path)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	before, e := root.Lstat("source")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(path, "source")); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Mkfifo(filepath.Join(path, "source"), 0600); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, e := boundedRead(root, "source", before); result <- e }()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO blocked inventory")
	}
}
