package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestA001SymlinkEscape(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if e := os.Symlink("/etc/passwd", filepath.Join(root, "escape")); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(root, "app_demo"); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestInventoryNeverExecutesLifecycle(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"next":"test"},"scripts":{"postinstall":"touch /tmp/aegis-executed"}}`), 0600)
	os.MkdirAll(filepath.Join(root, "app", "api", "accounts", "[id]"), 0700)
	os.WriteFile(filepath.Join(root, "app", "api", "accounts", "[id]", "route.ts"), []byte(`export async function GET(){}`), 0600)
	a, e := Read(root, "app_demo")
	if e != nil {
		t.Fatal(e)
	}
	b, e := Read(root, "app_demo")
	if e != nil || a.Digest != b.Digest {
		t.Fatal("unstable inventory")
	}
	if len(a.Routes) != 1 || a.Routes[0].Pattern != "/api/accounts/{parameter}" || a.Routes[0].Auth != "not assessed" {
		t.Fatal(a)
	}
	if len(a.Frameworks) != 1 || a.Frameworks[0] != "next" {
		t.Fatal(a)
	}
}
