// SPDX-License-Identifier: BUSL-1.1
// Package scannerdb provisions and verifies offline vulnerability databases for
// the pinned OSV-Scanner and Trivy images. Fetching is an explicit operator step
// (network, free public sources); scanner jobs only ever receive a verified,
// read-only copy and never network access. It has no executor or engine imports.
package scannerdb

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	Schema       = "1.0"
	ManifestName = "manifest.json"
	osvBase      = "https://osv-vulnerabilities.storage.googleapis.com/"
	maxOSVBytes  = 2 << 30
)

// DefaultEcosystems covers the package managers the bundled parsers handle.
var DefaultEcosystems = []string{"npm", "PyPI", "Go", "crates.io", "Maven", "RubyGems", "NuGet", "Packagist"}

var ecosystemShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{1,31}$`)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Database struct {
	Tool      string `json:"tool"`
	Source    string `json:"source"`
	BuiltAt   string `json:"upstream_built_at"`
	FetchedAt string `json:"fetched_at"`
	Files     []File `json:"files"`
	Digest    string `json:"digest"`
}

// Manifest is ScannerDatabaseManifestV1.
type Manifest struct {
	Schema    string     `json:"schema_version"`
	CreatedAt string     `json:"created_at"`
	Databases []Database `json:"databases"`
	Digest    string     `json:"manifest_digest"`
}

// Status is the verified view a scanner integration uses.
type Status struct {
	Tool     string  `json:"tool"`
	Digest   string  `json:"digest"`
	BuiltAt  string  `json:"upstream_built_at"`
	AgeHours float64 `json:"age_hours"`
	Stale    bool    `json:"stale"`
}

// Mount describes how a scanner container receives a database: read-only, at a
// fixed path, with the arguments/environment the tool needs to find it.
type Mount struct {
	HostPath      string   `json:"host_path"`
	ContainerPath string   `json:"container_path"`
	ReadOnly      bool     `json:"read_only"`
	ExtraArgs     []string `json:"extra_args"`
	Env           []string `json:"env"`
}

func digestOf(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func hashFile(path string) (File, error) {
	f, e := os.Open(path)
	if e != nil {
		return File{}, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	if e != nil {
		return File{}, e
	}
	return File{SHA256: "sha256:" + hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

// hashTree records every regular file under dir (relative paths, sorted) and
// refuses symlinks and other special files.
func hashTree(dir string) ([]File, error) {
	out := []File{}
	e := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unexpected non-regular file %s", p)
		}
		f, e := hashFile(p)
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(dir, p)
		f.Path = filepath.ToSlash(rel)
		out = append(out, f)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, e
}

// Databases are public advisory data, so directories are world-readable: Docker
// Desktop cannot bind-mount paths below a mode-0750 directory.
func staging(root string) (string, error) {
	b := make([]byte, 6)
	rand.Read(b)
	dir := filepath.Join(root, ".staging-"+hex.EncodeToString(b))
	return dir, os.MkdirAll(dir, 0755)
}

// install atomically replaces root/<tool> with the staged directory.
func install(root, tool, staged string) error {
	final := filepath.Join(root, tool)
	old := final + ".old"
	os.RemoveAll(old)
	if _, e := os.Stat(final); e == nil {
		if e = os.Rename(final, old); e != nil {
			return e
		}
	}
	if e := os.Rename(staged, final); e != nil {
		os.Rename(old, final)
		return e
	}
	return os.RemoveAll(old)
}

// FetchOSV downloads per-ecosystem OSV archives into root/osv using the layout
// OSV-Scanner v2 reads (osv-scalibr/<ecosystem>/all.zip).
func FetchOSV(ctx context.Context, root string, ecosystems []string, client *http.Client) (Database, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute}
	}
	if len(ecosystems) == 0 {
		ecosystems = DefaultEcosystems
	}
	dir, e := staging(root)
	if e != nil {
		return Database{}, e
	}
	defer os.RemoveAll(dir)
	newest := time.Time{}
	for _, eco := range ecosystems {
		if !ecosystemShape.MatchString(eco) {
			return Database{}, fmt.Errorf("invalid ecosystem %q", eco)
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", osvBase+eco+"/all.zip", nil)
		resp, e := client.Do(req)
		if e != nil {
			return Database{}, fmt.Errorf("download %s: %w", eco, e)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return Database{}, fmt.Errorf("download %s: HTTP %d", eco, resp.StatusCode)
		}
		if t, e := http.ParseTime(resp.Header.Get("Last-Modified")); e == nil && t.After(newest) {
			newest = t
		}
		path := filepath.Join(dir, "osv-scalibr", eco, "all.zip")
		os.MkdirAll(filepath.Dir(path), 0755)
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			resp.Body.Close()
			return Database{}, e
		}
		n, e := io.Copy(f, io.LimitReader(resp.Body, maxOSVBytes+1))
		resp.Body.Close()
		if ce := f.Close(); e == nil {
			e = ce
		}
		if e != nil || n > maxOSVBytes {
			return Database{}, fmt.Errorf("download %s failed or exceeded size limit", eco)
		}
		if e = checkZip(path); e != nil {
			return Database{}, fmt.Errorf("%s archive invalid: %w", eco, e)
		}
	}
	files, e := hashTree(dir)
	if e != nil {
		return Database{}, e
	}
	db := Database{Tool: "osv_v2", Source: osvBase + "{" + strings.Join(ecosystems, ",") + "}/all.zip", BuiltAt: newest.UTC().Format(time.RFC3339), FetchedAt: time.Now().UTC().Format(time.RFC3339), Files: files}
	db.Digest = digestOf(db.Files)
	if e = install(root, "osv", dir); e != nil {
		return Database{}, e
	}
	return db, nil
}

func checkZip(path string) error {
	r, e := zip.OpenReader(path)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".json") {
			return nil
		}
	}
	return errors.New("archive contains no advisories")
}

// FetchTrivy runs the pinned Trivy image once, with network, to download its
// vulnerability database into root/trivy. Only the operator runs this.
func FetchTrivy(ctx context.Context, root, image string) (Database, error) {
	if !strings.Contains(image, "@sha256:") {
		return Database{}, errors.New("trivy image must be pinned by digest")
	}
	dir, e := staging(root)
	if e != nil {
		return Database{}, e
	}
	defer os.RemoveAll(dir)
	abs, _ := filepath.Abs(dir)
	// Trivy downloads a large archive to its temp dir first; keep it on disk in
	// the staging area (removed before hashing), not in a small tmpfs.
	if e = os.MkdirAll(filepath.Join(dir, ".tmp"), 0755); e != nil {
		return Database{}, e
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "-e", "HOME=/tmp", "-e", "TMPDIR=/cache/.tmp",
		"--mount", "type=bind,src="+abs+",dst=/cache", image, "image", "--download-db-only", "--cache-dir", "/cache", "--no-progress")
	// Docker Desktop's file sharing can briefly report a just-created directory as
	// missing; retry only that specific refusal, a bounded number of times.
	for attempt := 1; ; attempt++ {
		run := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
		out, e := run.CombinedOutput()
		if e == nil {
			break
		}
		if attempt < 3 && strings.Contains(string(out), "bind source path does not exist") {
			time.Sleep(2 * time.Second)
			continue
		}
		return Database{}, fmt.Errorf("trivy database download failed: %s", lastLine(strings.TrimSpace(strings.ReplaceAll(string(out), "\nRun 'docker run --help' for more information", ""))))
	}
	if e = os.RemoveAll(filepath.Join(dir, ".tmp")); e != nil {
		return Database{}, e
	}
	var meta struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	b, e := os.ReadFile(filepath.Join(dir, "db", "metadata.json"))
	if e != nil || json.Unmarshal(b, &meta) != nil || meta.UpdatedAt.IsZero() {
		return Database{}, errors.New("trivy database metadata missing")
	}
	files, e := hashTree(dir)
	if e != nil {
		return Database{}, e
	}
	db := Database{Tool: "trivy", Source: image + " image --download-db-only", BuiltAt: meta.UpdatedAt.UTC().Format(time.RFC3339), FetchedAt: time.Now().UTC().Format(time.RFC3339), Files: files}
	db.Digest = digestOf(db.Files)
	if e = install(root, "trivy", dir); e != nil {
		return Database{}, e
	}
	return db, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	l := lines[len(lines)-1]
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}

// WriteManifest merges db into root/manifest.json, replacing any previous entry for the same tool.
func WriteManifest(root string, db Database) (Manifest, error) {
	m, _ := ReadManifest(root)
	kept := []Database{}
	for _, d := range m.Databases {
		if d.Tool != db.Tool {
			kept = append(kept, d)
		}
	}
	m = Manifest{Schema: Schema, CreatedAt: time.Now().UTC().Format(time.RFC3339), Databases: append(kept, db)}
	sort.Slice(m.Databases, func(i, j int) bool { return m.Databases[i].Tool < m.Databases[j].Tool })
	m.Digest = digestOf(m.Databases)
	b, _ := json.MarshalIndent(m, "", " ")
	tmp := filepath.Join(root, ManifestName+".tmp")
	if e := os.WriteFile(tmp, b, 0644); e != nil {
		return m, e
	}
	return m, os.Rename(tmp, filepath.Join(root, ManifestName))
}

func ReadManifest(root string) (Manifest, error) {
	var m Manifest
	b, e := os.ReadFile(filepath.Join(root, ManifestName))
	if e != nil {
		return m, e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.Schema != Schema || m.Digest != digestOf(m.Databases) {
		return m, errors.New("database manifest is malformed or was modified")
	}
	return m, nil
}

func toolDir(tool string) (string, error) {
	switch tool {
	case "osv_v2":
		return "osv", nil
	case "trivy":
		return "trivy", nil
	}
	return "", fmt.Errorf("no offline database for %s", tool)
}

// Verify rehashes every recorded file; any change, addition or removal fails.
// Databases older than maxAge are reported stale (still usable, but flagged).
func Verify(root string, maxAge time.Duration, now time.Time) ([]Status, error) {
	m, e := ReadManifest(root)
	if e != nil {
		return nil, e
	}
	out := []Status{}
	for _, db := range m.Databases {
		dir, e := toolDir(db.Tool)
		if e != nil {
			return nil, e
		}
		files, e := hashTree(filepath.Join(root, dir))
		if e != nil {
			return nil, e
		}
		if digestOf(files) != db.Digest {
			return nil, fmt.Errorf("%s database files do not match the manifest", db.Tool)
		}
		built, e := time.Parse(time.RFC3339, db.BuiltAt)
		if e != nil || built.IsZero() || built.Year() < 2000 {
			built, _ = time.Parse(time.RFC3339, db.FetchedAt)
		}
		age := now.Sub(built)
		out = append(out, Status{Tool: db.Tool, Digest: db.Digest, BuiltAt: built.UTC().Format(time.RFC3339), AgeHours: float64(int(age.Hours()*10)) / 10, Stale: age > maxAge})
	}
	return out, nil
}

// MountFor returns the read-only mount and the arguments/environment a scanner
// container needs to use the verified database for tool.
func MountFor(root, tool string) (Mount, error) {
	dir, e := toolDir(tool)
	if e != nil {
		return Mount{}, e
	}
	abs, e := filepath.Abs(filepath.Join(root, dir))
	if e != nil {
		return Mount{}, e
	}
	m := Mount{HostPath: abs, ContainerPath: "/db/" + dir, ReadOnly: true, ExtraArgs: []string{}, Env: []string{}}
	if tool == "trivy" {
		m.ExtraArgs = []string{"--cache-dir", "/db/trivy"}
	} else {
		m.Env = []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv"}
	}
	return m, nil
}
