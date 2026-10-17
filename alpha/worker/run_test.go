// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssetReferencesCannotBecomePathsOrSymlinks(t *testing.T) {
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "valid-asset"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("valid-asset", filepath.Join(dir, "alias")); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	for _, ref := range []string{"/tmp/source", "mounted-asset:../valid-asset", "mounted-asset:valid-asset/child", "mounted-asset:alias", "mounted-asset:", "mounted-asset:.git", "mounted-asset:missing", "https://example.test/repo"} {
		if opened, e := openAsset(root, ref); e == nil {
			opened.Close()
			t.Fatalf("unsafe asset accepted: %s", ref)
		}
	}
	opened, e := openAsset(root, "mounted-asset:valid-asset")
	if e != nil {
		t.Fatal(e)
	}
	opened.Close()
}

func TestOperatorRootsMustBeCanonicalDirectories(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(dir, "alias")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "file")
	if e = os.WriteFile(file, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"", ".", alias, file, dir + "/../" + filepath.Base(dir)} {
		if canonicalDir(p) {
			t.Fatalf("noncanonical root accepted: %s", p)
		}
	}
	if !canonicalDir(dir) {
		t.Fatal("canonical directory refused")
	}
}
