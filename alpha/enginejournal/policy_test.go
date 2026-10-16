//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package enginejournal

import (
	"aegis.local/source"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicySealRetainsExactConfigurationAndRefusesDowngrade(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	seal := source.Hash([]byte("local immutable configuration"))
	if e = j.RequirePolicy(seal); e != nil {
		t.Fatal(e)
	}
	if e = j.RequirePolicy(seal); e != nil {
		t.Fatal("exact repeat refused", e)
	}
	if j.RequirePolicy("") == nil || j.RequirePolicy(source.Hash([]byte("changed"))) == nil {
		t.Fatal("seal changed")
	}
	fullAttempt(t, j, "aegis-scan-"+strings.Repeat("a", 32))
	j.Close()
	j, e = OpenExisting(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.RequirePolicy(seal); e != nil {
		t.Fatal(e)
	}
	if j.RequirePolicy("") == nil {
		t.Fatal("reopened without policy")
	}
	o := j.Observe()
	if o.ControllerBound || o.ExclusiveOrigin || o.CleanupAuthorized {
		t.Fatal("local seal became external authority")
	}
	j.Close()
	if e = os.Remove(filepath.Join(path, "policy.json")); e != nil {
		t.Fatal(e)
	}
	if j, e = OpenExisting(path, engine); e == nil {
		j.Close()
		t.Fatal("deleted policy silently discarded attempt binding")
	}
}

func TestUsedUnboundNamespaceCannotAcquirePolicy(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	fullAttempt(t, j, "aegis-scan-"+strings.Repeat("b", 32))
	if j.RequirePolicy(source.Hash([]byte("new policy"))) == nil {
		t.Fatal("historic unbound attempts relabelled")
	}
	if e = j.RequirePolicy(""); e != nil {
		t.Fatal("legacy exact mode lost compatibility", e)
	}
}

func TestPolicySealRejectsTornAliasedLinkedAndMismatchedFiles(t *testing.T) {
	for _, kind := range []string{"torn", "unknown", "alias", "wrong-namespace", "hardlink", "symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			path, engine := journalFixture(t)
			j, e := Open(path, engine)
			if e != nil {
				t.Fatal(e)
			}
			if e = j.RequirePolicy(source.Hash([]byte("policy"))); e != nil {
				t.Fatal(e)
			}
			j.Close()
			p := filepath.Join(path, "policy.json")
			raw, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "torn":
				raw = raw[:len(raw)/2]
			case "unknown":
				raw = []byte(strings.Replace(string(raw), `"schema_version":"1.0"`, `"schema_version":"1.0","extra":true`, 1))
			case "alias":
				raw = []byte(strings.Replace(string(raw), "local_policy_digest", "Local_policy_digest", 1))
			case "wrong-namespace":
				raw = []byte(strings.Replace(string(raw), "namespace_digest", "different_namespace", 1))
			case "hardlink":
				if e = os.Link(p, filepath.Join(filepath.Dir(path), "linked-policy")); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e = os.Rename(p, filepath.Join(filepath.Dir(path), "original-policy")); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink("../original-policy", p); e != nil {
					t.Fatal(e)
				}
			case "public":
				if e = os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if kind != "hardlink" && kind != "symlink" && kind != "public" {
				if e = os.WriteFile(p, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if j, e = OpenExisting(path, engine); e == nil {
				j.Close()
				t.Fatal("invalid policy record reopened")
			}
		})
	}
}
