//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBoundBarrierRequiresOriginalNamespaceAndRefusesLegacyRelabel(t *testing.T) {
	root := initializedRegistry(t)
	l, e := openRegistry(root, false)
	if e != nil {
		t.Fatal(e)
	}
	namespace := l.namespace
	l.Close()
	if !engineDigest.MatchString(namespace) {
		t.Fatal("missing namespace identity")
	}
	if e = WithBoundEmptyRegistry(context.Background(), root, namespace, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"", "unknown", "sha256:" + strings.Repeat("f", 64)} {
		if e = WithBoundEmptyRegistry(context.Background(), root, bad, func() error { t.Fatal("wrong namespace reached callback"); return nil }); e == nil {
			t.Fatal("unapproved namespace accepted")
		}
	}
	legacy := filepath.Join(filepath.Dir(root), "legacy")
	s, e := Begin(legacy)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = WithBoundEmptyRegistry(context.Background(), legacy, namespace, func() error { t.Fatal("legacy namespace promoted"); return nil }); e == nil {
		t.Fatal("legacy namespace bound")
	}
	if _, e = os.Lstat(filepath.Join(legacy, registryNamespaceFile)); !os.IsNotExist(e) {
		t.Fatal("legacy namespace relabelled")
	}
}

func TestCopiedNamespaceCannotAuthenticateReplacementDirectory(t *testing.T) {
	root := initializedRegistry(t)
	l, e := openRegistry(root, false)
	if e != nil {
		t.Fatal(e)
	}
	original := l.namespace
	l.Close()
	b, e := os.ReadFile(filepath.Join(root, registryNamespaceFile))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(root, root+"-original"); e != nil {
		t.Fatal(e)
	}
	replacement, e := InitializeRegistryNamespace(context.Background(), root)
	if e != nil || replacement == original {
		t.Fatal("replacement did not get distinct namespace", e)
	}
	if e = WithBoundEmptyRegistry(context.Background(), root, original, func() error { t.Fatal("replacement accepted"); return nil }); e == nil {
		t.Fatal("stale root identity accepted")
	}
	if e = os.WriteFile(filepath.Join(root, registryNamespaceFile), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = WithBoundEmptyRegistry(context.Background(), root, original, func() error { t.Fatal("copied namespace accepted"); return nil }); e == nil {
		t.Fatal("copied physical scope accepted")
	}
	kept, e := os.ReadFile(filepath.Join(root, registryNamespaceFile))
	if e != nil || string(kept) != string(b) {
		t.Fatal("unknown replacement was repaired")
	}
}

func TestNamespaceTamperAndLinksAreRefusedWithoutRepair(t *testing.T) {
	for _, kind := range []string{"contents", "unknown-key", "duplicate-key", "mode", "symlink", "hardlink", "fifo", "missing"} {
		t.Run(kind, func(t *testing.T) {
			root := initializedRegistry(t)
			path := filepath.Join(root, registryNamespaceFile)
			l, e := openRegistry(root, false)
			if e != nil {
				t.Fatal(e)
			}
			namespace := l.namespace
			l.Close()
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "contents":
				os.WriteFile(path, []byte("{}\n"), 0600)
			case "unknown-key":
				os.WriteFile(path, []byte(strings.Replace(string(b), "{", "{\"grant\":true,", 1)), 0600)
			case "duplicate-key":
				os.WriteFile(path, []byte(strings.Replace(string(b), "{", "{\"schema_version\":\"1.0\",", 1)), 0600)
			case "mode":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+"-original")
				os.Symlink(registryNamespaceFile+"-original", path)
			case "hardlink":
				os.Link(path, path+"-alias")
			case "fifo":
				os.Remove(path)
				if e = syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "missing":
				os.Remove(path)
			}
			if e = WithBoundEmptyRegistry(context.Background(), root, namespace, func() error { t.Fatal("invalid namespace accepted"); return nil }); e == nil {
				t.Fatal("namespace was not refused")
			}
			if kind == "missing" {
				if _, e = os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("missing namespace recreated")
				}
			}
		})
	}
}

func TestCloseWaitsForGlobalProtocolAndRetainsLeaseOnContention(t *testing.T) {
	root := initializedRegistry(t)
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Preserve()
	barrier, e := openRegistry(root, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e == nil {
		t.Fatal("close crossed global barrier")
	}
	if _, e = s.lease.Stat(); e != nil {
		t.Fatal("contended close released lifecycle lease")
	}
	if _, e = os.Lstat(s.Path); e != nil {
		t.Fatal("contended close removed workspace")
	}
	barrier.Close()
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}
