// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package scanqueue

import (
	"aegis.local/source/scanevidence"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateLaunchContextExportRetainsOwnerAndNoCleanupAuthority(t *testing.T) {
	if os.Geteuid() <= 0 {
		t.Skip("positive operator UID required")
	}
	q, l, _, p := launchFixture(t)
	record, e := q.RegisterLaunch(l, p)
	if e != nil {
		t.Fatal(e)
	}
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(parent, 0700)
	path := filepath.Join(parent, "context.json")
	digest, e := q.ExportLaunchFile(l.Job.Owner, l.Job.ID, p.Tool, path)
	if e != nil || digest != record.Digest {
		t.Fatal(digest, e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("context is not private", e)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var got scanevidence.LaunchRecord
	if json.Unmarshal(b, &got) != nil || got.Digest != record.Digest || got.Document != record.Document {
		t.Fatal("export changed immutable context")
	}
	if _, e = q.ExportLaunchFile(l.Job.Owner, l.Job.ID, p.Tool, path); e == nil {
		t.Fatal("existing file overwritten")
	}
	same, _ := os.ReadFile(path)
	if string(same) != string(b) {
		t.Fatal("existing context changed")
	}
	if _, e = q.ExportLaunchFile("owner-b", l.Job.ID, p.Tool, filepath.Join(parent, "other.json")); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner export", e)
	}
	if _, e = q.ExportLaunchFile(l.Job.Owner, l.Job.ID, "unsupported", filepath.Join(parent, "missing.json")); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("unknown launch exported", e)
	}
	var state string
	q.S.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state)
	if state != "active" {
		t.Fatal("export changed admission", state)
	}
	os.Chmod(parent, 0755)
	if _, e = q.ExportLaunchFile(l.Job.Owner, l.Job.ID, p.Tool, filepath.Join(parent, "public.json")); e == nil {
		t.Fatal("nonprivate parent accepted")
	}
	os.Chmod(parent, 0700)
}
