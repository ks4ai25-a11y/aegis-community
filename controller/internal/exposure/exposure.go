// SPDX-License-Identifier: BUSL-1.1
// Package exposure compares routes declared in a repository's application map
// with route templates observed at the gateway (v4 manual E3). The comparison
// prioritises review; it is not evidence of an authorization weakness.
package exposure

import (
	"sort"
	"strings"
)

type Observed struct {
	Method string
	Route  string
	Count  int
}

type Entry struct {
	Route      string   `json:"route"`
	Category   string   `json:"category"`
	Methods    []string `json:"observed_methods"`
	Requests   int      `json:"requests_retained"`
	SourcePath string   `json:"source_path,omitempty"`
	Note       string   `json:"note,omitempty"`
}

type Report struct {
	Entries []Entry        `json:"entries"`
	Counts  map[string]int `json:"counts"`
	Limits  []string       `json:"limitations"`
}

func wildcard(s string) bool { return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") }

func split(route string) []string {
	return strings.Split(strings.Trim(route, "/"), "/")
}

// match compares segment by segment; placeholders on either side match any single segment.
func match(declared, observed string) bool {
	d, o := split(declared), split(observed)
	if len(d) != len(o) {
		return false
	}
	for i := range d {
		if d[i] != o[i] && !wildcard(d[i]) && !wildcard(o[i]) {
			return false
		}
	}
	return true
}

// literal reports whether an observed template keeps at least one real segment;
// "/{segment}" alone could be any route and is left unclassified.
func literal(route string) bool {
	if route == "/" {
		return true
	}
	for _, s := range split(route) {
		if !wildcard(s) {
			return true
		}
	}
	return false
}

// Compare classifies every declared and observed route as both, declared_only,
// observed_only or unclassified.
func Compare(declared map[string]string, observed []Observed) Report {
	r := Report{Entries: []Entry{}, Counts: map[string]int{"both": 0, "declared_only": 0, "observed_only": 0, "unclassified": 0},
		Limits: []string{
			"Declared routes come from file conventions only and do not prove reachability or authorization.",
			"Observed templates hide unknown path segments, so several declared routes can match one observed template.",
			"Methods for declared routes are not extracted; matching uses paths only.",
			"A route seen in traffic but not declared may be served by a framework, proxy or another repository.",
		}}
	grouped := map[string]*Entry{}
	order := []string{}
	for _, o := range observed {
		e, ok := grouped[o.Route]
		if !ok {
			e = &Entry{Route: o.Route, Methods: []string{}}
			grouped[o.Route] = e
			order = append(order, o.Route)
		}
		e.Requests += o.Count
		if o.Method != "" && !contains(e.Methods, o.Method) {
			e.Methods = append(e.Methods, o.Method)
		}
	}
	matchedDeclared := map[string]bool{}
	for _, route := range order {
		e := grouped[route]
		sort.Strings(e.Methods)
		if !literal(route) {
			e.Category, e.Note = "unclassified", "Template has no literal segment to compare."
		} else {
			e.Category = "observed_only"
			for d, src := range declared {
				if match(d, route) {
					matchedDeclared[d] = true
					e.Category, e.SourcePath = "both", src
				}
			}
		}
		r.Entries = append(r.Entries, *e)
	}
	paths := make([]string, 0, len(declared))
	for d := range declared {
		paths = append(paths, d)
	}
	sort.Strings(paths)
	for _, d := range paths {
		if !matchedDeclared[d] {
			r.Entries = append(r.Entries, Entry{Route: d, Category: "declared_only", Methods: []string{}, SourcePath: declared[d], Note: "Not seen in retained traffic; it may be unused, protected elsewhere or simply not requested yet."})
		}
	}
	for _, e := range r.Entries {
		r.Counts[e.Category]++
	}
	sort.SliceStable(r.Entries, func(i, j int) bool { return rank(r.Entries[i].Category) < rank(r.Entries[j].Category) })
	return r
}

func rank(c string) int {
	return map[string]int{"observed_only": 0, "both": 1, "declared_only": 2, "unclassified": 3}[c]
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
