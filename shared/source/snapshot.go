// SPDX-License-Identifier: BUSL-1.1
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Manifest identifies only the included read-only scanner input. It is not a
// proof of a clean Git checkout, complete repository coverage or exploitability.
type Manifest struct {
	Schema   string `json:"schema_version"`
	InputMap string `json:"input_map_digest"`
	Commit   string `json:"commit_sha"`
	Files    []File `json:"files"`
	Bytes    int64  `json:"included_bytes"`
	Digest   string `json:"snapshot_digest"`
}
type Snapshot struct {
	Path     string   `json:"-"`
	Manifest Manifest `json:"manifest"`
}

func mapDigest(m Map) string {
	m.Observed = ""
	m.Digest = ""
	b, _ := json.Marshal(m)
	return Hash(b)
}
func manifestDigest(m Manifest) string {
	m.Digest = ""
	b, _ := json.Marshal(m)
	return Hash(b)
}

// Capture copies exactly an approved inventory into a new private directory.
// scratchParent is provisioned by the local operator, never a browser path.
// No repository scripts, git commands, hooks or dependency installers execute.
func Capture(ctx context.Context, repository *os.Root, expected Map, scratchParent string) (out Snapshot, err error) {
	if expected.Schema != "1.0" || expected.App == "" || expected.SourceRef == "" || expected.Digest != mapDigest(expected) {
		return out, fmt.Errorf("invalid inventory identity")
	}
	current, e := ReadRootContext(ctx, repository, expected.App, expected.SourceRef)
	if e != nil || current.Digest != expected.Digest {
		return out, fmt.Errorf("repository changed since approved inventory")
	}
	scratch, e := filepath.Abs(scratchParent)
	if scratchParent == "" {
		scratch = os.TempDir()
		e = nil
	}
	if e != nil {
		return out, e
	}
	scratch, e = filepath.EvalSymlinks(scratch)
	if e != nil {
		return out, e
	}
	repositoryPath, e := filepath.Abs(repository.Name())
	if e != nil {
		return out, e
	}
	rel, e := filepath.Rel(repositoryPath, scratch)
	if e != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return out, fmt.Errorf("source scratch directory must be outside the repository")
	}
	path, e := os.MkdirTemp(scratch, "aegis-source-")
	if e != nil {
		return out, e
	}
	out.Path = path
	// The caller owns cleanup only after successful complete capture.
	defer func() {
		if err != nil {
			if cleanupErr := os.RemoveAll(path); cleanupErr != nil {
				err = fmt.Errorf("failed capture cleanup unconfirmed")
				return
			}
			out = Snapshot{}
		}
	}()
	root, e := os.OpenRoot(path)
	if e != nil {
		return out, e
	}
	defer root.Close()
	manifest := Manifest{Schema: "1.0", InputMap: expected.Digest, Commit: expected.Commit, Files: []File{}}
	for _, file := range expected.Files {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		if !fs.ValidPath(file.Path) || file.Size < 0 || file.Size > MaxFileBytes {
			return out, fmt.Errorf("invalid bounded source reference")
		}
		st, e := repository.Lstat(file.Path)
		if e != nil || !st.Mode().IsRegular() || st.Size() != file.Size {
			return out, fmt.Errorf("source changed during capture")
		}
		bytes, e := boundedRead(repository, file.Path, st)
		if e != nil || Hash(bytes) != file.Digest {
			return out, fmt.Errorf("source identity changed during capture")
		}
		manifest.Bytes += int64(len(bytes))
		if manifest.Bytes > MaxBytes {
			return out, fmt.Errorf("snapshot byte budget exceeded")
		}
		parent := filepath.Dir(file.Path)
		if e = root.MkdirAll(parent, 0700); e != nil {
			return out, e
		}
		// Exclusive creation prevents duplicate paths from overwriting prior input.
		f, e := root.OpenFile(file.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if e != nil {
			return out, e
		}
		_, writeErr := f.Write(bytes)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return out, fmt.Errorf("snapshot write failed")
		}
		manifest.Files = append(manifest.Files, file)
	}
	// Detect a checkout update during capture as well as checking each copied file.
	current, e = ReadRootContext(ctx, repository, expected.App, expected.SourceRef)
	if e != nil || current.Digest != expected.Digest {
		return out, fmt.Errorf("repository changed during capture")
	}
	manifest.Digest = manifestDigest(manifest)
	out.Manifest = manifest
	if e = ValidateSnapshot(ctx, root, manifest); e != nil {
		return out, e
	}
	return out, nil
}

// ValidateSnapshot proves the complete bounded file list and bytes immediately
// before execution. Read-only mounts must enforce immutability while a tool runs.
func ValidateSnapshot(ctx context.Context, root *os.Root, manifest Manifest) error {
	if manifest.Schema != "1.0" || manifest.InputMap == "" || manifest.Digest != manifestDigest(manifest) || len(manifest.Files) > 10000 || manifest.Bytes < 0 || manifest.Bytes > MaxBytes {
		return fmt.Errorf("invalid snapshot identity")
	}
	found := []File{}
	total := int64(0)
	e := walkBounded(root, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("snapshot symlink rejected")
		}
		if entry.IsDir() {
			return nil
		}
		st, e := root.Lstat(path)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
			return fmt.Errorf("snapshot file budget or type invalid")
		}
		b, e := boundedRead(root, path, st)
		if e != nil {
			return e
		}
		total += int64(len(b))
		if total > MaxBytes || len(found) >= 10000 {
			return fmt.Errorf("snapshot budget exceeded")
		}
		found = append(found, File{path, Hash(b), int64(len(b))})
		return nil
	})
	if e != nil {
		return e
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Path < found[j].Path })
	if total != manifest.Bytes || len(found) != len(manifest.Files) {
		return fmt.Errorf("snapshot file list differs")
	}
	for i, file := range found {
		if file != manifest.Files[i] {
			return fmt.Errorf("snapshot bytes or paths differ")
		}
	}
	return nil
}

// Close removes the private source workspace. Nothing is retained by default.
func (s *Snapshot) Close() error {
	if s.Path == "" {
		return nil
	}
	e := os.RemoveAll(s.Path)
	if e == nil {
		s.Path = ""
	}
	return e
}
