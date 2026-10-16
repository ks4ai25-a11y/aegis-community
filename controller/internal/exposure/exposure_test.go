package exposure

import "testing"

func TestCompareCategories(t *testing.T) {
	declared := map[string]string{"/api/users/{parameter}": "app/api/users/[id]/route.ts", "/api/health": "app/api/health/route.ts", "/api/admin/export": "app/api/admin/export/route.ts"}
	observed := []Observed{{"GET", "/api/users/{id}", 10}, {"POST", "/api/users/{id}", 2}, {"GET", "/api/health", 4}, {"GET", "/debug", 1}, {"GET", "/{segment}", 7}}
	r := Compare(declared, observed)
	want := map[string]string{"/api/users/{id}": "both", "/api/health": "both", "/debug": "observed_only", "/{segment}": "unclassified", "/api/admin/export": "declared_only"}
	got := map[string]string{}
	for _, e := range r.Entries {
		got[e.Route] = e.Category
	}
	for route, c := range want {
		if got[route] != c {
			t.Error(route, got[route], "want", c)
		}
	}
	if r.Counts["both"] != 2 || r.Counts["declared_only"] != 1 || r.Counts["observed_only"] != 1 || r.Counts["unclassified"] != 1 {
		t.Fatal(r.Counts)
	}
	for _, e := range r.Entries {
		if e.Route == "/api/users/{id}" && (e.Requests != 12 || len(e.Methods) != 2 || e.SourcePath == "") {
			t.Fatal(e)
		}
	}
	if r.Entries[0].Category != "observed_only" || len(r.Limits) == 0 {
		t.Fatal("observed-only routes should be listed first with limitations")
	}
}

func TestDifferentDepthNeverMatches(t *testing.T) {
	if match("/api/{parameter}", "/api/users/{id}") || !match("/", "/") {
		t.Fatal("depth mismatch")
	}
}
