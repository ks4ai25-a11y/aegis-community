// SPDX-License-Identifier: BUSL-1.1
package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func captureFixture(t *testing.T) (*os.Root, Map, string) {
	t.Helper()
	path, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(path, "src"), 0700)
	os.WriteFile(filepath.Join(path, "src", "query.py"), []byte("print('read only')"), 0600)
	os.WriteFile(filepath.Join(path, ".env"), []byte("PRIVATE_CANARY_NOT_FOR_SNAPSHOT"), 0600)
	root, e := os.OpenRoot(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	m, e := ReadRoot(root, "app_demo", "mounted-asset:fixture")
	if e != nil {
		t.Fatal(e)
	}
	return root, m, path
}
func TestCaptureExactInputAndCleanup(t *testing.T) {
	root, m, _ := captureFixture(t)
	s, e := Capture(context.Background(), root, m, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Manifest.Files) != 1 || s.Manifest.InputMap != m.Digest || s.Manifest.Bytes != int64(len("print('read only')")) {
		t.Fatal(s.Manifest)
	}
	if _, e = os.Stat(filepath.Join(s.Path, ".env")); !os.IsNotExist(e) {
		t.Fatal("protected file copied", e)
	}
	snapshot, e := os.OpenRoot(s.Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateSnapshot(context.Background(), snapshot, s.Manifest); e != nil {
		t.Fatal(e)
	}
	snapshot.Close()
	original := s.Path
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(original); !os.IsNotExist(e) {
		t.Fatal("snapshot retained", e)
	}
}
func TestCaptureRejectsStaleOrForgedMapWithoutArtifacts(t *testing.T) {
	root, m, path := captureFixture(t)
	scratch := t.TempDir()
	os.WriteFile(filepath.Join(path, "src", "query.py"), []byte("changed"), 0600)
	if _, e := Capture(context.Background(), root, m, scratch); e == nil {
		t.Fatal("stale inventory accepted")
	}
	entries, _ := os.ReadDir(scratch)
	if len(entries) != 0 {
		t.Fatal("failed capture retained source")
	}
	m.Digest = "sha256:forged"
	if _, e := Capture(context.Background(), root, m, scratch); e == nil {
		t.Fatal("forged inventory accepted")
	}
}
func TestSnapshotRejectsTamperingExtraFileAndCancellation(t *testing.T) {
	root, m, _ := captureFixture(t)
	s, e := Capture(context.Background(), root, m, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	snapshot, e := os.OpenRoot(s.Path)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	os.WriteFile(filepath.Join(s.Path, "extra"), []byte("unapproved"), 0600)
	if e = ValidateSnapshot(context.Background(), snapshot, s.Manifest); e == nil {
		t.Fatal("extra input accepted")
	}
	os.Remove(filepath.Join(s.Path, "extra"))
	os.Chmod(filepath.Join(s.Path, "src", "query.py"), 0600)
	os.WriteFile(filepath.Join(s.Path, "src", "query.py"), []byte("different"), 0600)
	if e = ValidateSnapshot(context.Background(), snapshot, s.Manifest); e == nil {
		t.Fatal("changed input accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = Capture(ctx, root, m, t.TempDir()); e == nil {
		t.Fatal("cancelled capture accepted")
	}
}

func TestCaptureRefusesWorkspaceInsideReadOnlySource(t *testing.T) {
	root, m, path := captureFixture(t)
	if _, e := Capture(context.Background(), root, m, path); e == nil {
		t.Fatal("source directory accepted as scratch workspace")
	}
}
