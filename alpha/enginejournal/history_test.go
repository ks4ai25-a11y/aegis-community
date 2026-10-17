//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package enginejournal

import (
	"aegis.local/source"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func historyFiles(t *testing.T, path string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(path, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == ".lock" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(path, p)
		if err == nil {
			files[rel] = source.Hash(b)
		}
		return err
	})
	if err != nil {
		t.Fatal("journal snapshot unavailable")
	}
	return files
}

func TestKnownContainerHistorySurvivesRestartWithoutAuthorityOrWrites(t *testing.T) {
	path, engine := journalFixture(t)
	j, err := Open(path, engine)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"aegis-scan-" + strings.Repeat("a", 32), "aegis-scan-" + strings.Repeat("b", 32)}
	ids := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	for n := range names {
		if j.KnownContainer(names[n]) || j.KnownContainer(ids[n]) {
			t.Fatal("unknown allocation recognized before its durable record")
		}
		a, err := j.Begin(names[n], source.Hash([]byte("descriptor")))
		if err != nil {
			t.Fatal(err)
		}
		if !j.KnownContainer(names[n]) || j.KnownContainer(ids[n]) {
			t.Fatal("manifest acquired an unconfirmed native ID")
		}
		created, err := a.Begin("create", "")
		if err != nil || created.Confirm(201, ids[n]) != nil {
			t.Fatal("create record unavailable", err)
		}
		removed, err := a.Begin("remove", ids[n])
		if err != nil || removed.Confirm(204, ids[n]) != nil || a.Finish() != nil {
			t.Fatal("remove record unavailable", err)
		}
	}
	beforeFiles, beforeState := historyFiles(t, path), j.Observe()
	check := func(j *Journal) {
		t.Helper()
		for n := range names {
			if !j.KnownContainer(names[n]) || !j.KnownContainer(ids[n]) {
				t.Fatal("earlier exact allocation identity was lost")
			}
		}
		for _, unknown := range []string{"", "aegis-scan-" + strings.Repeat("c", 32), strings.Repeat("c", 64), ids[0][:12], "/" + names[0], names[0] + "/json", strings.ToUpper(ids[0])} {
			if j.KnownContainer(unknown) {
				t.Fatal("non-exact identity acquired journal read access")
			}
		}
		state := j.Observe()
		if state != beforeState || state.ControllerBound || state.ExclusiveOrigin || state.CleanupAuthorized {
			t.Fatal("metadata recognition changed lifecycle or authority")
		}
	}
	check(j)
	j.Close()
	if j.KnownContainer(names[0]) || j.KnownContainer(ids[0]) {
		t.Fatal("closed journal retained read authority")
	}
	j, err = OpenExisting(path, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	check(j)
	if !reflect.DeepEqual(beforeFiles, historyFiles(t, path)) {
		t.Fatal("history reads or restart rewrote retained evidence")
	}
}

func TestKnownContainerPendingCreateNeverInventsIDOrSettlesUncertainty(t *testing.T) {
	path, engine := journalFixture(t)
	j, err := Open(path, engine)
	if err != nil {
		t.Fatal(err)
	}
	name := "aegis-scan-" + strings.Repeat("d", 32)
	id := strings.Repeat("d", 64)
	a, err := j.Begin(name, source.Hash([]byte("descriptor")))
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := a.Begin("create", "")
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Confirm(500, id) == nil || j.KnownContainer(id) {
		t.Fatal("failed create response invented a known native ID")
	}
	before := historyFiles(t, path)
	j.Close()
	j, err = OpenExisting(path, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	state := j.Observe()
	if !j.KnownContainer(name) || j.KnownContainer(id) || state.Unresolved != 1 || state.Unfinished != 1 || state.CleanupAuthorized {
		t.Fatal("history read discharged an unknown create")
	}
	if !reflect.DeepEqual(before, historyFiles(t, path)) {
		t.Fatal("uncertain history was repaired by observation")
	}
}
