//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeaseJournalAndRecovery(t *testing.T) {
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(parent, "registry")
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-0123456789abcdef0123456789abcdef"
	if e = s.Bind(name); e != nil {
		t.Fatal(e)
	}
	if e = s.Bind(name); e == nil {
		t.Fatal("container rebound")
	}
	future := time.Now().Add(4 * time.Minute)
	r, e := Recover(context.Background(), root, future, nil)
	if e != nil || r.Active != 1 {
		t.Fatalf("live lease: %+v %v", r, e)
	}
	s.Preserve()
	r, e = Recover(context.Background(), root, time.Now(), nil)
	if e != nil || r.Deferred != 1 {
		t.Fatalf("grace: %+v %v", r, e)
	}
	r, e = Recover(context.Background(), root, future, func(_ context.Context, id string) (bool, error) {
		if id != name {
			t.Fatal("wrong container")
		}
		return false, nil
	})
	if e != nil || r.Deferred != 1 {
		t.Fatalf("active container: %+v %v", r, e)
	}
	r, e = Recover(context.Background(), root, future, func(context.Context, string) (bool, error) { return true, nil })
	if e != nil || r.Removed != 1 {
		t.Fatalf("orphan: %+v %v", r, e)
	}
	if _, e = os.Stat(s.Path); !os.IsNotExist(e) {
		t.Fatal("orphan retained")
	}
}
func TestRecoveryRefusesSymlinkAndInvalidJournal(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(parent, "registry")
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	s.Preserve()
	if e = os.WriteFile(filepath.Join(s.Path, "journal.json"), []byte(`{"schema_version":"1.0","created_unix":1,"container":"unrelated"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Recover(context.Background(), root, time.Now(), func(context.Context, string) (bool, error) {
		t.Fatal("invalid identity reached Docker")
		return true, nil
	}); e == nil {
		t.Fatal("invalid journal accepted")
	}
	os.RemoveAll(s.Path)
	outside := filepath.Join(parent, "keep")
	os.Mkdir(outside, 0700)
	os.Symlink(outside, s.Path)
	if _, e = Recover(context.Background(), root, time.Now(), nil); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e = os.Stat(outside); e != nil {
		t.Fatal("unrelated directory touched")
	}
}
