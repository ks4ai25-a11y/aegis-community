// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
)

// ExportLaunchFile writes owner-checked metadata, not a cleanup capability.
// The receiving observer still needs a separately authenticated authority path.
func (q *Queue) ExportLaunchFile(owner, job, tool, path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrInput
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return "", ErrInput
	}
	directory, e := privateExportParent(parent)
	if e != nil {
		return "", e
	}
	defer directory.Close()
	records, e := q.Launches(owner, job)
	if e != nil {
		return "", e
	}
	var b []byte
	digest := ""
	for _, record := range records {
		if record.Document.Plan.Tool == tool {
			b, e = json.Marshal(record)
			if e != nil {
				return "", e
			}
			digest = record.Digest
			break
		}
	}
	if digest == "" {
		return "", sql.ErrNoRows
	}
	if len(b) > 8192 {
		return "", ErrInput
	}
	f, e := directory.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", ErrInput
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			directory.Remove(filepath.Base(path))
		}
	}()
	if _, e = f.Write(append(b, '\n')); e != nil {
		return "", e
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	complete = true
	return digest, nil
}
