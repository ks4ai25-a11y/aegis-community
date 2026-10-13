//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestLeaseJournalAndRecovery(t *testing.T) {
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(parent, "registry")
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-0123456789abcdef0123456789abcdef"
	if e = s.Bind(name, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); e != nil {
		t.Fatal(e)
	}
	if e = s.Bind(name, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); e == nil {
		t.Fatal("container rebound")
	}
	future := time.Now().Add(4 * time.Minute)
	r, e := Recover(context.Background(), root, future, nil)
	if e != nil || r.Active != 1 {
		t.Fatalf("live lease: %+v %v", r, e)
	}
	s.Preserve()
	r, e = Recover(context.Background(), root, time.Now(), nil)
	if e != nil || r.Deferred != 1 {
		t.Fatalf("grace: %+v %v", r, e)
	}
	r, e = Recover(context.Background(), root, future, func(_ context.Context, id, engine string) (bool, error) {
		if id != name {
			t.Fatal("wrong container")
		}
		return false, nil
	})
	if e != nil || r.Deferred != 1 {
		t.Fatalf("active container: %+v %v", r, e)
	}
	r, e = Recover(context.Background(), root, future, func(context.Context, string, string) (bool, error) { return true, nil })
	if e != nil || r.Removed != 1 {
		t.Fatalf("orphan: %+v %v", r, e)
	}
	if _, e = os.Stat(s.Path); !os.IsNotExist(e) {
		t.Fatal("orphan retained")
	}
}
func TestRecoveryRefusesSymlinkAndInvalidJournal(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(parent, "registry")
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	s.Preserve()
	if e = os.WriteFile(filepath.Join(s.Path, "journal.json"), []byte(`{"schema_version":"1.0","created_unix":1,"container":"unrelated"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Recover(context.Background(), root, time.Now(), func(context.Context, string, string) (bool, error) {
		t.Fatal("invalid identity reached Docker")
		return true, nil
	}); e == nil {
		t.Fatal("invalid journal accepted")
	}
	os.RemoveAll(s.Path)
	outside := filepath.Join(parent, "keep")
	os.Mkdir(outside, 0700)
	os.Symlink(outside, s.Path)
	if _, e = Recover(context.Background(), root, time.Now(), nil); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e = os.Stat(outside); e != nil {
		t.Fatal("unrelated directory touched")
	}
}

func TestRecoveryRejectsJournalFIFOWithoutBlocking(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(parent, "registry")
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	s.Preserve()
	journal := filepath.Join(s.Path, "journal.json")
	if e = os.Remove(journal); e != nil {
		t.Fatal(e)
	}
	if e = syscall.Mkfifo(journal, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Recover(context.Background(), root, time.Now().Add(4*time.Minute), nil); e == nil {
		t.Fatal("nonregular journal accepted")
	}
}

func TestSingleRunAdmissionIncludesUnrecoveredOrphans(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(parent, "registry")
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Begin(root); !errors.Is(e, ErrOccupied) {
		t.Fatal("second live scanner admitted", e)
	}
	s.Preserve()
	if _, e = Begin(root); !errors.Is(e, ErrOccupied) {
		t.Fatal("unrecovered orphan ignored", e)
	}
	if _, e = Recover(context.Background(), root, time.Now().Add(4*time.Minute), nil); e != nil {
		t.Fatal(e)
	}
	replacement, e := Begin(root)
	if e != nil {
		t.Fatal("recovered registry could not accept a scan", e)
	}
	defer replacement.Close()
}
func TestConcurrentAdmissionNeverCreatesTwoSessions(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(parent, "registry")
	// Provision the registry first, so the race tests admission rather than
	// directory creation or a trusted operator provisioning mistake.
	seed, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = seed.Close(); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	sessions := make(chan *Session, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if s, e := Begin(root); e == nil {
				sessions <- s
			}
		}()
	}
	close(start)
	wg.Wait()
	close(sessions)
	count := 0
	for s := range sessions {
		count++
		defer s.Close()
	}
	if count != 1 {
		t.Fatalf("admitted %d simultaneous sessions", count)
	}
}

func TestReservedWorkspaceAuthorizesBeforeAllocationAndJournalsAcknowledgement(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(parent, "registry")
	reservation := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	s, e := BeginReserved(root, func(id string) (string, error) {
		if !sessionName.MatchString(id) {
			t.Fatal("unsafe reserved id")
		}
		if _, e := os.Lstat(filepath.Join(root, id)); !os.IsNotExist(e) {
			t.Fatal("workspace allocated before acknowledgement")
		}
		if _, e := Begin(root); e == nil {
			t.Fatal("reservation released registry admission")
		}
		return reservation, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(s.Path, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	var r record
	if json.Unmarshal(b, &r) != nil || r.Reservation != reservation || r.Container != "" {
		t.Fatal("reservation not journaled before capture")
	}
	s.Preserve()
	got, e := Recover(context.Background(), root, time.Now().Add(4*time.Minute), nil)
	if e != nil || got.Removed != 1 {
		t.Fatal("container-free capture orphan not recoverable", got, e)
	}
}
func TestFailedWorkspaceAuthorizationCreatesNoRun(t *testing.T) {
	for _, kind := range []string{"lost_ack", "invalid_digest", "nil"} {
		t.Run(kind, func(t *testing.T) {
			parent, _ := filepath.EvalSymlinks(t.TempDir())
			root := filepath.Join(parent, "registry")
			authorize := func(string) (string, error) {
				if kind == "lost_ack" {
					return "", errors.New("lost acknowledgement")
				}
				return "wrong", nil
			}
			if kind == "nil" {
				authorize = nil
			}
			if _, e := BeginReserved(root, authorize); e == nil {
				t.Fatal("unauthorized allocation accepted")
			}
			entries, e := os.ReadDir(root)
			if e != nil && !os.IsNotExist(e) {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if entry.Name() != ".registry-lock" {
					t.Fatal("refusal left a run directory")
				}
			}
		})
	}
}
