// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuardLoaderRefusesUnprovisionedAndWrongArtifacts(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "text", "wrong_arch", "fake_elf", "budget"} {
		t.Run(kind, func(t *testing.T) {
			dir, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			a := filepath.Join(dir, "scanner-guard-linux-amd64")
			b := filepath.Join(dir, "scanner-guard-linux-arm64")
			if kind != "missing" {
				data := make([]byte, 64)
				copy(data, []byte("\x7fELF"))
				data[4] = 2
				data[5] = 1
				data[18] = 183
				if kind == "text" {
					data = []byte("not executable")
				}
				if kind == "fake_elf" {
					data[18] = 62
				}
				if kind == "budget" {
					data = make([]byte, (32<<20)+1)
				}
				if e = os.WriteFile(a, data, 0500); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(b, data, 0500); e != nil {
					t.Fatal(e)
				}
				if kind == "symlink" {
					os.Remove(a)
					if e = os.Symlink(b, a); e != nil {
						t.Fatal(e)
					}
				}
			}
			if _, e = LoadGuards(dir); e == nil {
				t.Fatal("invalid packaged guard accepted")
			}
		})
	}
	if _, e := LoadGuards("relative"); e == nil {
		t.Fatal("relative artifact root accepted")
	}
}
