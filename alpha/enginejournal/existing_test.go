//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package enginejournal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenExistingNeverInitializesMissingStateAndHoldsLifetimeLock(t *testing.T) {
	path, engine := journalFixture(t)
	if j, e := OpenExisting(path, engine); e == nil {
		j.Close()
		t.Fatal("missing initialized")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("directory allocated")
	}
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	before := j.Observe()
	j.Close()
	existing, e := OpenExisting(path, engine)
	if e != nil || existing.Observe() != before {
		t.Fatal(e)
	}
	if other, e := OpenExisting(path, engine); e == nil {
		other.Close()
		t.Fatal("concurrent bound writer")
	}
	existing.Close()
	if e = os.Remove(filepath.Join(path, "identity.json")); e != nil {
		t.Fatal(e)
	}
	if j, e := OpenExisting(path, engine); e == nil {
		j.Close()
		t.Fatal("missing identity repaired")
	}
	if _, e := os.Stat(filepath.Join(path, "identity.json")); !os.IsNotExist(e) {
		t.Fatal("identity recreated")
	}
}

func TestInitializeEmptyDoesNotRepairExistingLockOrIdentity(t *testing.T) {
	for _, kind := range []string{"lock", "identity", "partial", "used", "valid"} {
		t.Run(kind, func(t *testing.T) {
			path, engine := journalFixture(t)
			first, e := InitializeEmpty(path, engine)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "lock":
				if e = os.Remove(filepath.Join(path, ".lock")); e != nil {
					t.Fatal(e)
				}
			case "identity":
				if e = os.Remove(filepath.Join(path, "identity.json")); e != nil {
					t.Fatal(e)
				}
			case "partial":
				if e = os.RemoveAll(path); e != nil {
					t.Fatal(e)
				}
				if e = os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "used":
				j, e := OpenExisting(path, engine)
				if e != nil {
					t.Fatal(e)
				}
				fullAttempt(t, j, "aegis-scan-"+strings.Repeat("b", 32))
				j.Close()
			}
			before, e := os.ReadDir(path)
			if e != nil {
				t.Fatal(e)
			}
			again, e := InitializeEmpty(path, engine)
			if kind == "valid" {
				if e != nil || again != first {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unsafe initialization", kind)
			}
			after, e := os.ReadDir(path)
			if e != nil || len(before) != len(after) {
				t.Fatal("initialization repaired state", kind, e)
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("files changed", kind)
				}
			}
		})
	}
}
