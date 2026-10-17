package remediate

import (
	"aegis.local/controller/internal/assess"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const file = "import sqlite3\n\ndef find(db, name):\n    return db.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"

const good = `--- a/query.py
+++ b/query.py
@@ -3,2 +3,2 @@
 def find(db, name):
-    return db.execute("SELECT * FROM users WHERE name = '%s'" % name)
+    return db.execute("SELECT * FROM users WHERE name = ?", (name,))
`

func TestApplyAcceptsExactDiff(t *testing.T) {
	out, e := Apply(file, "query.py", good)
	if e != nil || !strings.Contains(out, "(name,)") || strings.Contains(out, "% name") {
		t.Fatal(out, e)
	}
}

func TestApplyRejectsUnsafeDiffs(t *testing.T) {
	bad := map[string]string{
		"other file":    strings.ReplaceAll(good, "query.py", "../../etc/passwd"),
		"wrong context": strings.Replace(good, " def find(db, name):", " def find(db, user):", 1),
		"new file":      "--- /dev/null\n+++ b/x.py\n@@ -0,0 +1 @@\n+x\n",
		"no hunks":      "--- a/query.py\n+++ b/query.py\n",
		"prose":         "Here is the fix:\n" + good,
		"out of range":  strings.Replace(good, "@@ -3,2 +3,2 @@", "@@ -90,2 +90,2 @@", 1),
		"no-op":         "--- a/query.py\n+++ b/query.py\n@@ -3,1 +3,1 @@\n def find(db, name):\n",
	}
	for name, d := range bad {
		if _, e := Apply(file, "query.py", d); e == nil {
			t.Error(name, "accepted")
		}
	}
}

func TestGuidanceIsCategorySpecific(t *testing.T) {
	s := Guidance(Finding{Category: "secret_candidate", Path: ".env.example"})
	if s.Priority != "P1" || !strings.Contains(s.Steps[0], "Revoke") || !s.Advisory {
		t.Fatal(s)
	}
	d := Guidance(Finding{Category: "known_vulnerable_dependency", Package: "lodash", Installed: "4.17.15", Advisories: []string{"GHSA-x"}})
	if !strings.Contains(d.Title, "lodash") || !strings.Contains(d.Steps[0], "GHSA-x") {
		t.Fatal(d)
	}
	q := Guidance(Finding{Category: "static_pattern", Path: "query.py", Line: 4, RuleIDs: []string{"B608"}})
	if !strings.Contains(q.Steps[0], "bound parameters") {
		t.Fatal(q)
	}
	for _, bad := range []Finding{{Category: "configuration_claim"}, {Category: "static_pattern", Path: "../x"}, {Category: "static_pattern", Path: "/etc/passwd"}} {
		if bad.Validate() == nil {
			t.Error("accepted", bad)
		}
	}
}

func TestDraftPatchBuildsDiffFromBoundedEdit(t *testing.T) {
	reply := map[string]any{"start_line": 4, "end_line": 4, "replacement_lines": []string{`    return db.execute("SELECT * FROM users WHERE name = ?", (name,))`}, "explanation": "Use a bound parameter."}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(reply)
		json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": string(b)}})
	}))
	defer srv.Close()
	c := assess.Config{Provider: "ollama", URL: srv.URL, Model: "m", Timeout: 5 * time.Second}
	f := Finding{Category: "static_pattern", Path: "query.py", Line: 4, RuleIDs: []string{"B608"}}
	d, e := DraftPatch(context.Background(), c, f, "query.py", file)
	if e != nil || !strings.Contains(d.Diff, "+    return db.execute(\"SELECT * FROM users WHERE name = ?\", (name,))") || !strings.Contains(d.Diff, "-    return db.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)") {
		t.Fatal(d, e)
	}
	patched, e := Apply(file, "query.py", d.Diff)
	if e != nil || !strings.Contains(patched, "(name,)") {
		t.Fatal(patched, e)
	}
	for _, bad := range []map[string]any{
		{"start_line": 1, "end_line": 1, "replacement_lines": []string{"x"}, "explanation": ""},            // nearby but leaves the finding's line unchanged
		{"start_line": 40, "end_line": 41, "replacement_lines": []string{"x"}, "explanation": ""},          // out of file
		{"start_line": 4, "end_line": 4, "replacement_lines": []string{"a\nimport os"}, "explanation": ""}, // smuggled newline
		{"start_line": 0, "end_line": 0, "replacement_lines": []string{}, "explanation": "no fix"},
	} {
		reply = bad
		d, e := DraftPatch(context.Background(), c, f, "query.py", file)
		if e == nil {
			t.Fatal("accepted", bad, d)
		}
	}
	if _, e := Build("query.py", strings.Split(file, "\n"), 4, 3, 5, []string{"a", "b", "c"}); e != nil {
		t.Fatal("edit covering the finding refused", e)
	}
	far := Finding{Category: "static_pattern", Path: "query.py", Line: 40}
	if _, e := Build("query.py", strings.Split(file, "\n"), far.Line, 1, 1, []string{"x"}); e == nil {
		t.Fatal("edit far from finding accepted")
	}
	if _, e = DraftPatch(context.Background(), c, Finding{Category: "secret_candidate"}, "x", file); e == nil {
		t.Fatal("secret draft generated")
	}
}

func TestBalancedRejectsBrokenEdits(t *testing.T) {
	if !balanced(file) {
		t.Fatal("fixture should balance")
	}
	broken := "def q(db, x):\n    return db.execute(\n    'SELECT ?'\n    x\n"
	if balanced(broken) {
		t.Fatal("unclosed call accepted")
	}
	if !balanced("s = \"(not a bracket\"  # ) neither\nf(a[0], {1: 2})\n") {
		t.Fatal("strings or comments miscounted")
	}
}
