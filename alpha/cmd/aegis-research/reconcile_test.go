// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateRefusesLinksSharedModesAndRelativePaths(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "config.json")
	if err = os.WriteFile(good, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := readPrivate(good, 64); err != nil || string(b) != "{}" {
		t.Fatal("private file refused", err)
	}
	shared := filepath.Join(dir, "shared.json")
	os.WriteFile(shared, []byte(`{}`), 0644)
	link := filepath.Join(dir, "link.json")
	os.Symlink(good, link)
	hard := filepath.Join(dir, "hard.json")
	os.Link(good, hard)
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, make([]byte, 65), 0600)
	for _, path := range []string{shared, link, hard, big, "config.json", dir + "/./config.json"} {
		if _, err := readPrivate(path, 64); err == nil {
			t.Fatal("unsafe private file accepted:", path)
		}
	}
}
