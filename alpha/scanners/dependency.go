// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func boundedCoordinate(s string, max int, required bool) bool {
	if len(s) > max || required && s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// Coordinate bytes are identity data, never score or exploitability evidence.
func dependencyIdentity(f *Finding, purl, name, version, advisory string) error {
	if !boundedCoordinate(name, 256, true) || !boundedCoordinate(version, 128, true) || !boundedCoordinate(purl, 1024, false) || purl != "" && !strings.HasPrefix(purl, "pkg:") {
		return fmt.Errorf("invalid bounded dependency coordinate")
	}
	f.Package = purl
	f.PackageName = name
	f.Version = version
	f.Advisories = []string{advisory}
	// Length-separated JSON hashing avoids delimiter ambiguity and distinguishes
	// versions/packages sharing the same advisory and source lockfile.
	f.ID = identityHash([]string{f.App, f.Repository, f.Category, advisory, f.Path, purl, name, version})
	return nil
}
func percentComponent(s string) string {
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for _, b := range []byte(s) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b)) {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[b>>4])
			out.WriteByte(digits[b&15])
		}
	}
	return out.String()
}

// Known mappings only. Unknown OSV ecosystems retain the declared package name
// and version without inventing a package-url type.
func osvCoordinate(ecosystem, name, version string) (string, error) {
	if !boundedCoordinate(ecosystem, 64, true) || !boundedCoordinate(name, 256, true) || !boundedCoordinate(version, 128, true) {
		return "", fmt.Errorf("invalid OSV package coordinate")
	}
	switch ecosystem {
	case "npm":
		parts := strings.Split(name, "/")
		if len(parts) == 1 && parts[0] != "" && !strings.HasPrefix(name, "@") {
			return "pkg:npm/" + percentComponent(name) + "@" + percentComponent(version), nil
		}
		if len(parts) == 2 && strings.HasPrefix(parts[0], "@") && len(parts[0]) > 1 && parts[1] != "" {
			return "pkg:npm/" + percentComponent(parts[0]) + "/" + percentComponent(parts[1]) + "@" + percentComponent(version), nil
		}
		return "", fmt.Errorf("invalid npm namespace")
	case "PyPI":
		if strings.Contains(name, "/") {
			return "", fmt.Errorf("PyPI namespace prohibited")
		}
		normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		return "pkg:pypi/" + percentComponent(normalized) + "@" + percentComponent(strings.ToLower(version)), nil
	default:
		return "", nil
	}
}
