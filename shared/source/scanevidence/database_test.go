// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func dependencyFixture(t *testing.T, tool string) (Execution, Expected) {
	r, x := fixture()
	x.Tool, x.Tools, r.Tool = tool, []string{tool}, tool
	r.Invocation, _ = BuildDatabaseInvocation(tool)
	r.Exit = 0
	r.Result.Findings = []Finding{}
	path, _ := DatabaseContainerPath(tool)
	r.Database = &DatabaseUse{ManifestDigest: source.Hash([]byte("manifest")), Digest: source.Hash([]byte("db")), BuiltAt: "2026-10-16T00:00:00Z", AgeHours: 30, ContainerPath: path}
	x.Database = r.Database.Digest
	return r, x
}

func TestDatabaseInvocationIsFixed(t *testing.T) {
	i, e := BuildDatabaseInvocation("trivy")
	if e != nil || strings.Join(i.Args, " ") != "fs --scanners vuln --skip-db-update --skip-java-db-update --offline-scan --format json --cache-dir /db/trivy /src" {
		t.Fatal(i, e)
	}
	o, _ := BuildDatabaseInvocation("osv_v2")
	plain, _ := BuildInvocation("osv_v2")
	if !reflect.DeepEqual(o, plain) {
		t.Fatal("OSV argv changed; its database comes from the environment")
	}
	if _, e := BuildDatabaseInvocation("bandit"); e == nil {
		t.Fatal("non-advisory tool given a database invocation")
	}
}

func TestOnlyApprovedFreshDatabaseIsCurrent(t *testing.T) {
	for _, tool := range []string{"osv_v2", "trivy"} {
		r, x := dependencyFixture(t, tool)
		got, e := Normalize(r, x)
		if e != nil || got.Status != "completed" || !strings.Contains(strings.Join(got.Limitations, " "), "approved offline database") {
			t.Fatal(tool, got.Status, e)
		}
		// Round trip through the canonical decoder.
		b, _ := json.Marshal(got)
		if d, e := Decode(b); e != nil || d.Database == nil || d.Database.Digest != r.Database.Digest {
			t.Fatal("database receipt does not decode", e)
		}
		cases := map[string]func(*Execution, *Expected){
			"stale":        func(r *Execution, x *Expected) { r.Database.Stale = true },
			"not approved": func(r *Execution, x *Expected) { x.Database = "" },
			"other digest": func(r *Execution, x *Expected) { x.Database = source.Hash([]byte("other")) },
		}
		for name, change := range cases {
			r, x := dependencyFixture(t, tool)
			change(&r, &x)
			got, e := Normalize(r, x)
			if e != nil || got.Status != "completed_stale_db" {
				t.Fatal(tool, name, got.Status, e)
			}
		}
		refused := map[string]func(*Execution, *Expected){
			"path":          func(r *Execution, x *Expected) { r.Database.ContainerPath = "/src" },
			"digest format": func(r *Execution, x *Expected) { r.Database.Digest = "md5:x"; x.Database = r.Database.Digest },
			"built time":    func(r *Execution, x *Expected) { r.Database.BuiltAt = "yesterday" },
			"negative age":  func(r *Execution, x *Expected) { r.Database.AgeHours = -1 },
			"plain argv": func(r *Execution, x *Expected) {
				r.Invocation, _ = BuildInvocation(tool)
				r.Invocation.Args = append(r.Invocation.Args, "x")
			},
			"database absent": func(r *Execution, x *Expected) {
				r.Database = nil
				r.Invocation, _ = BuildInvocation(tool)
				r.Invocation.Args = append([]string{"--cache-dir", "/tmp"}, r.Invocation.Args...)
			},
		}
		for name, change := range refused {
			r, x := dependencyFixture(t, tool)
			change(&r, &x)
			if _, e := Normalize(r, x); e == nil {
				t.Fatal(tool, name, "accepted")
			}
		}
	}
	r, x := fixture()
	r.Database = &DatabaseUse{ManifestDigest: source.Hash([]byte("m")), Digest: source.Hash([]byte("d")), BuiltAt: "2026-10-16T00:00:00Z", ContainerPath: "/db/osv"}
	if _, e := Normalize(r, x); e == nil {
		t.Fatal("database accepted for a non-advisory tool")
	}
	b, _ := json.Marshal(r)
	if _, e := Decode([]byte(strings.Replace(string(b), `"stale":false`, `"stale":false,"extra":1`, 1))); e == nil {
		t.Fatal("unknown database field decoded")
	}
}
