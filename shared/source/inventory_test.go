package source

import (
	"encoding/json"
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
	marker := filepath.Join(root, "lifecycle-executed")
	config, _ := json.Marshal(map[string]any{"dependencies": map[string]string{"next": "test"}, "scripts": map[string]string{"postinstall": "touch " + marker}})
	os.WriteFile(filepath.Join(root, "package.json"), config, 0600)
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
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("inventory executed a lifecycle script", err)
	}
	if len(a.Frameworks) != 1 || a.Frameworks[0] != "next" {
		t.Fatal(a)
	}
}

func TestBoundedReadRejectsReplacementAndGrowth(t *testing.T) {
	rootPath, _ := filepath.EvalSymlinks(t.TempDir())
	file := filepath.Join(rootPath, "source.py")
	if err := os.WriteFile(file, []byte("benign"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := root.Lstat("source.py")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc/passwd", file); err != nil {
		t.Fatal(err)
	}
	if _, err = boundedRead(root, "source.py", before); err == nil {
		t.Fatal("replacement escaped root")
	}
	os.Remove(file)
	os.WriteFile(file, []byte("small"), 0600)
	before, _ = root.Lstat("source.py")
	os.WriteFile(file, make([]byte, MaxFileBytes+1), 0600)
	if _, err = boundedRead(root, "source.py", before); err == nil {
		t.Fatal("grown file accepted")
	}
}

func TestCommitMetadataIsDataAndRootRouteIsDeclared(t *testing.T) {
	rootPath, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(rootPath, ".git", "refs", "heads"), 0700)
	os.WriteFile(filepath.Join(rootPath, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0600)
	hash := "0123456789012345678901234567890123456789"
	os.WriteFile(filepath.Join(rootPath, ".git", "refs", "heads", "main"), []byte(hash+"\n"), 0600)
	os.MkdirAll(filepath.Join(rootPath, "app"), 0700)
	os.WriteFile(filepath.Join(rootPath, "app", "route.ts"), []byte("export const GET = () => {}"), 0600)
	m, err := Read(rootPath, "app_demo")
	if err != nil {
		t.Fatal(err)
	}
	if m.Commit != hash || len(m.Routes) != 1 || m.Routes[0].Pattern != "/" || m.Routes[0].Origin != "declared_route" {
		t.Fatal(m)
	}
	os.WriteFile(filepath.Join(rootPath, ".git", "HEAD"), []byte("ref: refs/heads/../../../../etc/passwd"), 0600)
	m, err = Read(rootPath, "app_demo")
	if err != nil || m.Commit != "" {
		t.Fatalf("metadata traversal: %s, %v", m.Commit, err)
	}
}

func TestInventoryOversizedFile(t *testing.T) {
	rootPath, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(rootPath, "oversized"), make([]byte, MaxFileBytes+1), 0600)
	if _, err := Read(rootPath, "app_demo"); err == nil {
		t.Fatal("oversized file accepted")
	}
}
