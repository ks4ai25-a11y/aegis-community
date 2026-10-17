// SPDX-License-Identifier: Apache-2.0
package source

import (
	"regexp"
	"strings"
)

// Static route extraction for Express, FastAPI and Flask. Source text is read,
// never executed. Only receivers created in the same file by the framework's own
// constructor are recognised, so calls such as axios.get("/api") or dict.get("/x")
// are not routes. Registrations with computed paths, routers mounted from other
// files and middleware applied elsewhere are not resolved; such routes keep low
// confidence and the map's unknowns say so.

var routeExtractors = []Extractor{{"express-literal-routes", "1.0"}, {"fastapi-decorators", "1.0"}, {"flask-decorators", "1.0"}}

const maxRoutesPerFile = 500

var (
	jsApp       = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express|require\(\s*['"]express['"]\s*\))\s*\(\s*\)`)
	jsRouter    = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?(?:express\s*\.\s*)?Router\s*\(`)
	jsRoute     = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*(['"` + "`" + `])(/[^'"` + "`" + `\s]{0,400})(['"` + "`" + `])\s*([,)])`)
	jsMount     = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*['"](/[^'"\s]{0,200})['"]\s*,\s*([A-Za-z_$][\w$]*)\s*\)`)
	pyFastAPI   = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:fastapi\.)?FastAPI\s*\(`)
	pyAPIRouter = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:fastapi\.)?APIRouter\s*\(([^)]{0,400})\)`)
	pyFlask     = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:flask\.)?Flask\s*\(`)
	pyBlueprint = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:flask\.)?Blueprint\s*\(([^)]{0,400})\)`)
	pyPrefix    = regexp.MustCompile(`\b(?:prefix|url_prefix)\s*=\s*['"](/[^'"\s]{0,200})['"]`)
	pyDecorator = regexp.MustCompile(`^\s*@\s*([A-Za-z_]\w*)\s*\.\s*(get|post|put|patch|delete|options|head|route|api_route)\s*\(\s*[rbu]?['"](/[^'"\s]{0,400}|)['"]([^\n]*)$`)
	pyMethods   = regexp.MustCompile(`methods\s*=\s*[\[(]([^\])]{0,200})[\])]`)
	pyWord      = regexp.MustCompile(`['"]([A-Za-z]+)['"]`)
	pathParam   = regexp.MustCompile(`:[A-Za-z_]\w*\??|\{[^}/]{1,64}\}|<[^>/]{1,64}>|\*`)
	authName    = regexp.MustCompile(`(?i)\b[\w.]*(auth|login_required|jwt_required|require_?user|current_user|verify_?token|ensure_?logged_?in|is_?authenticated|permission|security)\w*`)
)

func normalisePattern(p string) string {
	p = strings.SplitN(strings.SplitN(p, "?", 2)[0], "#", 2)[0]
	p = pathParam.ReplaceAllString(p, "{parameter}")
	if p == "" {
		p = "/"
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func joinPrefix(prefix, p string) string {
	if prefix == "" || prefix == "/" {
		return p
	}
	if p == "/" || p == "" {
		return strings.TrimSuffix(prefix, "/")
	}
	return strings.TrimSuffix(prefix, "/") + p
}

func auth(s string) string {
	if authName.MatchString(s) {
		return "auth_middleware_named"
	}
	return "not assessed"
}

func names(re *regexp.Regexp, text string) map[string]string {
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(text, 64) {
		prefix := ""
		if len(m) > 2 {
			if p := pyPrefix.FindStringSubmatch(m[2]); p != nil {
				prefix = p[1]
			}
		}
		out[m[1]] = prefix
	}
	return out
}

// extractRoutes returns routes declared in one source file.
func extractRoutes(rel string, b []byte) []Route {
	lower := strings.ToLower(rel)
	switch {
	case strings.HasSuffix(lower, ".d.ts"), strings.Contains(lower, ".test."), strings.Contains(lower, ".spec."), strings.HasPrefix(lower, "test/"), strings.HasPrefix(lower, "tests/"), strings.Contains(lower, "/test/"), strings.Contains(lower, "/tests/"):
		return nil
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".mjs"), strings.HasSuffix(lower, ".cjs"), strings.HasSuffix(lower, ".ts"):
		return expressRoutes(rel, string(b))
	case strings.HasSuffix(lower, ".py"):
		return pythonRoutes(rel, string(b))
	}
	return nil
}

func expressRoutes(rel, text string) []Route {
	if !strings.Contains(text, "express") {
		return nil
	}
	apps, routers := names(jsApp, text), names(jsRouter, text)
	if len(apps) == 0 && len(routers) == 0 {
		return nil
	}
	// Same-file mounts: app.use("/api", router) prefixes that router's routes.
	mounted := map[string]string{}
	for _, m := range jsMount.FindAllStringSubmatch(text, 64) {
		if _, ok := apps[m[1]]; ok {
			if _, ok := routers[m[3]]; ok {
				mounted[m[3]] = m[2]
			}
		}
	}
	out := []Route{}
	for _, idx := range jsRoute.FindAllStringSubmatchIndex(text, maxRoutesPerFile) {
		m := func(i int) string { return text[idx[2*i]:idx[2*i+1]] }
		receiver, quote, closing := m(1), m(3), m(5)
		if quote != closing || quote == "`" && strings.Contains(m(4), "${") {
			continue
		}
		_, isApp := apps[receiver]
		_, isRouter := routers[receiver]
		if !isApp && !isRouter {
			continue
		}
		pattern, confidence := normalisePattern(m(4)), "medium"
		if isRouter {
			if prefix, ok := mounted[receiver]; ok {
				pattern = normalisePattern(joinPrefix(prefix, m(4)))
			} else {
				confidence = "low" // mounted from another file; the prefix is unknown
			}
		}
		// Middleware between the path and the handler, on the same statement.
		end := idx[1] + 300
		if end > len(text) {
			end = len(text)
		}
		args := text[idx[1]:end]
		if i := strings.IndexAny(args, ";\n"); i >= 0 {
			args = args[:i] // this statement only
		}
		if i := strings.Index(args, "=>"); i >= 0 {
			args = args[:i]
		}
		if i := strings.Index(args, "function"); i >= 0 {
			args = args[:i]
		}
		method := strings.ToUpper(m(2))
		out = append(out, Route{method, pattern, "declared_route", auth(args), confidence, rel})
	}
	return out
}

func pythonRoutes(rel, text string) []Route {
	fast := strings.Contains(text, "fastapi")
	flask := strings.Contains(text, "flask")
	if !fast && !flask {
		return nil
	}
	receivers := map[string]string{} // name -> prefix
	kinds := map[string]string{}
	add := func(m map[string]string, kind string) {
		for k, v := range m {
			receivers[k], kinds[k] = v, kind
		}
	}
	if fast {
		add(names(pyFastAPI, text), "fastapi")
		add(names(pyAPIRouter, text), "fastapi-router")
	}
	if flask {
		add(names(pyFlask, text), "flask")
		add(names(pyBlueprint, text), "flask-blueprint")
	}
	lines := strings.Split(text, "\n")
	out := []Route{}
	for i, line := range lines {
		m := pyDecorator.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		receiver, verb, path, rest := m[1], m[2], m[3], m[4]
		kind, ok := kinds[receiver]
		if !ok {
			continue
		}
		methods := []string{strings.ToUpper(verb)}
		switch verb {
		case "route", "api_route":
			if strings.HasPrefix(kind, "fastapi") && verb == "route" {
				continue
			}
			methods = []string{"GET"}
			if mm := pyMethods.FindStringSubmatch(rest); mm != nil {
				methods = nil
				for _, w := range pyWord.FindAllStringSubmatch(mm[1], 8) {
					methods = append(methods, strings.ToUpper(w[1]))
				}
			} else if strings.Contains(rest, "methods") {
				methods = []string{"unknown"} // computed method list
			}
		}
		// Authentication signals: stacked decorators above, the decorator's own
		// arguments, and FastAPI dependencies in the handler signature below.
		context := rest
		for j := i - 1; j >= 0 && j >= i-6 && strings.HasPrefix(strings.TrimSpace(lines[j]), "@"); j-- {
			context += " " + lines[j]
		}
		for j := i + 1; j < len(lines) && j <= i+8; j++ {
			context += " " + lines[j]
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "def ") || strings.HasPrefix(strings.TrimSpace(lines[j]), "async def ") {
				if strings.Contains(lines[j], "):") {
					break
				}
			}
		}
		signal := "not assessed"
		if strings.HasPrefix(kind, "fastapi") {
			if strings.Contains(context, "Depends(") || strings.Contains(context, "Security(") {
				signal = auth(context)
			}
		} else {
			signal = auth(context)
		}
		confidence := "medium"
		prefix := receivers[receiver]
		if (kind == "fastapi-router" || kind == "flask-blueprint") && prefix == "" {
			confidence = "low" // included elsewhere, possibly with a prefix
		}
		for _, method := range methods {
			if len(out) >= maxRoutesPerFile {
				return out
			}
			if !validMethod(method) {
				method = "unknown"
			}
			out = append(out, Route{method, normalisePattern(joinPrefix(prefix, path)), "declared_route", signal, confidence, rel})
		}
	}
	return out
}

func validMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ALL", "unknown":
		return true
	}
	return false
}

// pythonFrameworks reads declared dependencies from requirements files and pyproject.toml.
func pythonFrameworks(rel string, b []byte) []string {
	name := rel[strings.LastIndex(rel, "/")+1:]
	if rel != name || !(strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") || name == "pyproject.toml" || name == "Pipfile") {
		return nil
	}
	out := []string{}
	text := strings.ToLower(string(b))
	for _, f := range []string{"fastapi", "flask"} {
		if regexp.MustCompile(`(?m)(^|["'\s])` + f + `\b`).MatchString(text) {
			out = append(out, f)
		}
	}
	return out
}
