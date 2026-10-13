// SPDX-License-Identifier: Apache-2.0
package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxBytes = 64 << 20
const MaxFileBytes = 1 << 20

type File struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}
type Route struct {
	Method     string `json:"method"`
	Pattern    string `json:"pattern"`
	Origin     string `json:"origin"`
	Auth       string `json:"auth_signal"`
	Confidence string `json:"confidence"`
	Path       string `json:"source_path"`
}
type Extractor struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type Map struct {
	SourceRef      string      `json:"source_ref"`
	Commit         string      `json:"commit_sha"`
	Observed       string      `json:"observed_at"`
	Extractors     []Extractor `json:"extractors"`
	SensitiveOps   []string    `json:"sensitive_ops"`
	Models         []string    `json:"models"`
	AuthBoundaries []string    `json:"auth_boundaries"`
	Schema         string      `json:"schema_version"`
	App            string      `json:"application_id"`
	Frameworks     []string    `json:"frameworks"`
	Files          []File      `json:"files"`
	Routes         []Route     `json:"routes"`
	Unknowns       []string    `json:"unknowns"`
	Digest         string      `json:"content_digest"`
}

func Hash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// Read operates only below an explicitly approved repository root. No dependencies are installed, no source is executed, and symlinks are rejected.
func Read(root, app string) (Map, error) {
	abs, e := filepath.Abs(root)
	if e != nil {
		return Map{}, e
	}
	real, e := filepath.EvalSymlinks(abs)
	if e != nil || real != abs {
		return Map{}, fmt.Errorf("repository root must be canonical and symlink-free")
	}
	anchor, e := os.OpenRoot(real)
	if e != nil {
		return Map{}, e
	}
	defer anchor.Close()
	return ReadRoot(anchor, app, "operator-mounted-directory")
}

// ReadRoot never follows a path outside an already provisioned directory handle.
// It does not execute git, package managers, lifecycle scripts or source code.
func ReadRoot(anchor *os.Root, app, sourceRef string) (Map, error) {
	return ReadRootContext(context.Background(), anchor, app, sourceRef)
}

func ReadRootContext(ctx context.Context, anchor *os.Root, app, sourceRef string) (Map, error) {
	m := Map{Schema: "1.0", App: app, SourceRef: sourceRef, Observed: time.Now().UTC().Format(time.RFC3339Nano), Extractors: []Extractor{{"next-file-conventions", "1.1"}}, SensitiveOps: []string{}, Models: []string{}, AuthBoundaries: []string{}, Frameworks: []string{}, Files: []File{}, Routes: []Route{}, Unknowns: []string{"Declared route files do not prove runtime reachability or authorization enforcement.", "Dynamic registration, server actions, cross-file ownership and database semantics are not yet assessed.", "The content digest covers included working-tree files, not a proof that the checkout is clean. Protected files and generated directories are omitted."}}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	m.Commit = readCommit(anchor)
	if m.Commit == "" {
		m.Unknowns = append(m.Unknowns, "Commit identity unavailable; no commit provenance claim.")
	}
	total := int64(0)
	entries := 0
	e := walkBounded(anchor, func(rel string, d fs.DirEntry, err error) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		entries++
		if entries > 20000 || len(rel) > 512 || strings.Count(rel, "/") > 64 || !utf8.ValidString(rel) {
			return fmt.Errorf("repository path budget exceeded")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("repository symlink rejected: %s", rel)
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".venv", "venv", ".next", "dist", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case ".env", ".env.local", "id_rsa", "id_ed25519":
			return nil
		}
		if strings.HasPrefix(d.Name(), ".env.") || strings.HasSuffix(d.Name(), ".pem") || strings.HasSuffix(d.Name(), ".key") {
			return nil
		}
		st, e := anchor.Lstat(rel)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("nonregular file rejected")
		}
		if st.Size() > MaxFileBytes {
			return fmt.Errorf("file size limit exceeded")
		}
		if total+st.Size() > MaxBytes || len(m.Files) >= 10000 {
			return fmt.Errorf("repository budget exceeded")
		}
		b, e := boundedRead(anchor, rel, st)
		if e != nil {
			return e
		}
		total += int64(len(b))
		if total > MaxBytes {
			return fmt.Errorf("repository byte budget exceeded")
		}
		rel = filepath.ToSlash(rel)
		m.Files = append(m.Files, File{rel, Hash(b), int64(len(b))})
		if rel == "package.json" {
			var p struct {
				Dependencies map[string]string `json:"dependencies"`
				Dev          map[string]string `json:"devDependencies"`
			}
			if json.Unmarshal(b, &p) == nil {
				for _, framework := range []string{"next", "express", "fastify"} {
					if p.Dependencies[framework] != "" || p.Dev[framework] != "" {
						m.Frameworks = append(m.Frameworks, framework)
					}
				}
			}
		}
		if strings.HasPrefix(rel, "app/") || strings.HasPrefix(rel, "src/app/") {
			if strings.HasSuffix(rel, "/route.ts") || strings.HasSuffix(rel, "/route.js") {
				prefix := strings.TrimPrefix(strings.TrimPrefix(rel, "src/"), "app/")
				prefix = filepath.ToSlash(filepath.Dir(prefix))
				if prefix == "." {
					prefix = ""
				}
				parts := strings.Split(prefix, "/")
				out := []string{}
				for _, v := range parts {
					if v == "" {
						continue
					}
					if strings.HasPrefix(v, "(") && strings.HasSuffix(v, ")") {
						continue
					}
					if strings.HasPrefix(v, "[") {
						v = "{parameter}"
					}
					out = append(out, v)
				}
				m.Routes = append(m.Routes, Route{"unknown", "/" + strings.Join(out, "/"), "declared_route", "not assessed", "low", rel})
			}
		}
		if strings.HasPrefix(rel, "pages/api/") || strings.HasPrefix(rel, "src/pages/api/") {
			prefix := strings.TrimPrefix(strings.TrimPrefix(rel, "src/"), "pages")
			prefix = strings.TrimSuffix(strings.TrimSuffix(prefix, ".ts"), ".js")
			prefix = strings.TrimSuffix(prefix, "/index")
			m.Routes = append(m.Routes, Route{"unknown", prefix, "declared_route", "not assessed", "low", rel})
		}
		return nil
	})
	if e != nil {
		return m, e
	}
	if ctx.Err() != nil {
		return m, ctx.Err()
	}
	if readCommit(anchor) != m.Commit {
		return m, fmt.Errorf("commit metadata changed during inventory")
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	sort.Strings(m.Frameworks)
	identity := m
	identity.Observed = ""
	b, _ := json.Marshal(identity)
	m.Digest = Hash(b)
	return m, nil
}

func boundedRead(root *os.Root, path string, expected fs.FileInfo) ([]byte, error) {
	f, err := openNonblocking(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(expected, actual) || actual.Size() != expected.Size() || !actual.ModTime().Equal(expected.ModTime()) || actual.Size() > MaxFileBytes {
		return nil, fmt.Errorf("source changed or is not a bounded regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil || len(b) > MaxFileBytes || int64(len(b)) != actual.Size() {
		return nil, fmt.Errorf("source read budget or consistency failure")
	}
	after, err := f.Stat()
	if err != nil || actual.Size() != after.Size() || !actual.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("source changed during read")
	}
	return b, nil
}

func metadata(root *os.Root, path string) string {
	st, err := root.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return ""
	}
	b, err := boundedRead(root, path, st)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func commitHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func readCommit(root *os.Root) string {
	st, err := root.Lstat(".git")
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	git, err := root.OpenRoot(".git")
	if err != nil {
		return ""
	}
	defer git.Close()
	head := metadata(git, "HEAD")
	if commitHash(head) {
		return head
	}
	if !strings.HasPrefix(head, "ref: refs/heads/") {
		return ""
	}
	ref := strings.TrimPrefix(head, "ref: ")
	if strings.Contains(ref, "..") || strings.ContainsAny(ref, "\\\x00\n\r") || len(ref) > 256 {
		return ""
	}
	h := metadata(git, ref)
	if commitHash(h) {
		return h
	}
	// Packed refs are bounded separately and are parsed as data, never executed.
	packed := metadata(git, "packed-refs")
	for _, line := range strings.Split(packed, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == ref && commitHash(fields[0]) {
			return fields[0]
		}
	}
	return ""
}
