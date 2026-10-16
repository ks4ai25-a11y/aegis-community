//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package engineauthz

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPinnedLockFileBoundaries(t *testing.T) {
	images, raw, e := ReadLock("../../tools/scanners.lock.json")
	if e != nil || len(images) != 6 {
		t.Fatal("repository lock", e)
	}
	for _, kind := range []string{"symlink", "hardlink", "fifo", "oversize", "unknown", "duplicate", "aliased"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "lock.json")
			switch kind {
			case "symlink":
				target, _ := filepath.Abs("../../tools/scanners.lock.json")
				e = os.Symlink(target, path)
			case "hardlink":
				target := filepath.Join(dir, "target")
				os.WriteFile(target, raw, 0600)
				e = os.Link(target, path)
			case "fifo":
				e = syscall.Mkfifo(path, 0600)
			case "oversize":
				e = os.WriteFile(path, []byte(strings.Repeat(" ", 65537)), 0600)
			case "unknown":
				e = os.WriteFile(path, append([]byte(`{"unknown":true,`), raw[1:]...), 0600)
			case "duplicate":
				e = os.WriteFile(path, append([]byte(`{"schema_version":"1.0",`), raw[1:]...), 0600)
			case "aliased":
				e = os.WriteFile(path, []byte(strings.Replace(string(raw), `"bandit"`, `"shell"`, 1)), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e = ReadLock(path); e == nil {
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}
