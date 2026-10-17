//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func initializedRegistry(t *testing.T) string {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("unprivileged operator required")
	}
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(parent, "registry")
	if e = InitializeRegistry(context.Background(), root); e != nil {
		t.Fatal(e)
	}
	return root
}

func TestEmptyRegistryBarrierUsesReadOnlyDescriptorAndExcludesCreation(t *testing.T) {
	root := initializedRegistry(t)
	l, e := openRegistry(root, false)
	if e != nil {
		t.Fatal(e)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, l.lock.Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		t.Fatal("observer opened writable lock")
	}
	l.Close()
	called := false
	e = WithEmptyRegistry(context.Background(), root, func() error {
		called = true
		if _, e := Begin(root); e == nil {
			t.Fatal("creation crossed barrier")
		}
		if _, e := Recover(context.Background(), root, time.Time{}, nil); e == nil {
			t.Fatal("recovery crossed barrier")
		}
		return nil
	})
	if e != nil || !called {
		t.Fatal("empty barrier callback unavailable", e)
	}
	s, e := Begin(root)
	if e != nil {
		t.Fatal("barrier leaked lock", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestBarrierNeverInitializesOrRepairsMissingState(t *testing.T) {
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(parent, "absent")
	callback := func() error { t.Fatal("unknown registry reached callback"); return nil }
	if e = WithEmptyRegistry(context.Background(), root, callback); e == nil {
		t.Fatal("missing registry accepted")
	}
	if _, e = os.Lstat(root); !os.IsNotExist(e) {
		t.Fatal("observer created registry")
	}
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e = WithEmptyRegistry(context.Background(), root, callback); e == nil {
		t.Fatal("missing lock accepted")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 0 {
		t.Fatal("observer repaired registry")
	}
	if e = InitializeRegistry(context.Background(), root); e == nil {
		t.Fatal("partial namespace reset")
	}
}

func TestBarrierRefusesActiveOrUnknownWorkspaceAndDetectsCallbackChanges(t *testing.T) {
	root := initializedRegistry(t)
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	called := false
	if e = WithEmptyRegistry(context.Background(), root, func() error { called = true; return nil }); !errors.Is(e, ErrOccupied) || called {
		t.Fatal("active workspace accepted", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(root, "unknown-state")
	e = WithEmptyRegistry(context.Background(), root, func() error { return os.WriteFile(marker, []byte("retain"), 0600) })
	if !errors.Is(e, ErrOccupied) {
		t.Fatal("changed registry accepted", e)
	}
	if b, e := os.ReadFile(marker); e != nil || string(b) != "retain" {
		t.Fatal("unknown state removed")
	}
}

func TestBarrierCancellationErrorAndPanicReleaseOnlyItsLock(t *testing.T) {
	for _, kind := range []string{"before", "during", "error", "panic"} {
		t.Run(kind, func(t *testing.T) {
			root := initializedRegistry(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "before" {
				cancel()
			}
			called := false
			func() {
				defer func() {
					if r := recover(); r != nil && kind != "panic" {
						t.Fatal("unexpected panic")
					}
				}()
				e := WithEmptyRegistry(ctx, root, func() error {
					called = true
					if kind == "during" {
						cancel()
					}
					if kind == "error" {
						return errors.New("callback refused")
					}
					if kind == "panic" {
						panic("synthetic callback panic")
					}
					return nil
				})
				if e == nil {
					t.Fatal("failed callback reported success")
				}
			}()
			if kind == "before" && called {
				t.Fatal("cancelled callback invoked")
			}
			if e := WithEmptyRegistry(context.Background(), root, func() error { return nil }); e != nil {
				t.Fatal("barrier leaked after callback failure", e)
			}
		})
	}
}

func TestCloseRefusesChangedRegistryWorkspaceLeaseAndPublicPath(t *testing.T) {
	for _, kind := range []string{"registry", "lock", "workspace", "lease", "public-path"} {
		t.Run(kind, func(t *testing.T) {
			root := initializedRegistry(t)
			s, e := Begin(root)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Preserve()
			outside := filepath.Join(filepath.Dir(root), "unrelated")
			os.Mkdir(outside, 0700)
			sentinel := filepath.Join(outside, "keep")
			os.WriteFile(sentinel, []byte("retain"), 0600)
			switch kind {
			case "registry":
				if e = os.Rename(root, root+"-original"); e != nil {
					t.Fatal(e)
				}
				if e = InitializeRegistry(context.Background(), root); e != nil {
					t.Fatal(e)
				}
			case "lock":
				if e = os.Rename(filepath.Join(root, ".registry-lock"), filepath.Join(root, "original-lock")); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(root, ".registry-lock"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "workspace":
				if e = os.Rename(s.Path, s.Path+"-original"); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(outside, s.Path); e != nil {
					t.Fatal(e)
				}
			case "lease":
				if e = os.Rename(filepath.Join(s.Path, "lease"), filepath.Join(s.Path, "original-lease")); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(s.Path, "lease"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "public-path":
				s.Path = outside
			}
			if e = s.Close(); e == nil {
				t.Fatal("substituted close accepted")
			}
			if b, e := os.ReadFile(sentinel); e != nil || string(b) != "retain" {
				t.Fatal("unrelated bytes changed")
			}
		})
	}
}

func TestUncertainLeaseCloseRetainsDirectoryAndRefusesBarrier(t *testing.T) {
	root := initializedRegistry(t)
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Preserve()
	if e = s.lease.Close(); e != nil {
		t.Fatal(e)
	} // Inject loss of the owned lease descriptor.
	if e = s.Close(); e == nil {
		t.Fatal("uncertain lease close succeeded")
	}
	if _, e = os.Lstat(s.Path); e != nil {
		t.Fatal("workspace deleted before confirmed lease close")
	}
	if e = WithEmptyRegistry(context.Background(), root, func() error { t.Fatal("unknown state reached callback"); return nil }); !errors.Is(e, ErrOccupied) {
		t.Fatal(e)
	}
}

func TestFailedDirectoryRemovalCanRetryAfterConfirmedLeaseClosure(t *testing.T) {
	root := initializedRegistry(t)
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	blocked := filepath.Join(s.Path, "blocked")
	os.Mkdir(blocked, 0700)
	os.WriteFile(filepath.Join(blocked, "keep"), []byte("private"), 0600)
	os.Chmod(blocked, 0000)
	t.Cleanup(func() { os.Chmod(blocked, 0700); s.Preserve() })
	if e = s.Close(); e == nil || s.lease != nil || !s.cleanupPending {
		t.Fatal("uncertain removal not retained", e)
	}
	if e = WithEmptyRegistry(context.Background(), root, func() error { t.Fatal("partial removal accepted"); return nil }); e == nil {
		t.Fatal("occupied registry accepted")
	}
	if e = os.Chmod(blocked, 0700); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal("known closed lease could not finish cleanup", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal("completed close not idempotent")
	}
	if e = WithEmptyRegistry(context.Background(), root, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
}

func TestConcurrentBindAndCloseHaveNoPostCloseWrites(t *testing.T) {
	root := initializedRegistry(t)
	s, e := Begin(root)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = s.Bind("aegis-scan-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	}()
	go func() {
		defer wg.Done()
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	wg.Wait()
	if _, e = os.Lstat(s.Path); !os.IsNotExist(e) {
		t.Fatal("workspace remains after concurrent close")
	}
}

func TestDelayedReservationCannotCrossEmptyRegistryBarrier(t *testing.T) {
	root := initializedRegistry(t)
	started, allow := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(allow) }) })
	type result struct {
		s *Session
		e error
	}
	done := make(chan result, 1)
	go func() {
		s, e := BeginReserved(root, func(string) (string, error) {
			close(started)
			<-allow
			return "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil
		})
		done <- result{s, e}
	}()
	select {
	case <-started:
	case r := <-done:
		t.Fatal("reservation did not enter callback", r.e)
	case <-time.After(2 * time.Second):
		t.Fatal("reservation callback unavailable")
	}
	if e := WithEmptyRegistry(context.Background(), root, func() error { t.Fatal("delayed reservation crossed barrier"); return nil }); e == nil {
		t.Fatal("pending creation accepted")
	}
	once.Do(func() { close(allow) })
	r := <-done
	if r.e != nil {
		t.Fatal(r.e)
	}
	if e := WithEmptyRegistry(context.Background(), root, func() error { t.Fatal("active workspace crossed barrier"); return nil }); !errors.Is(e, ErrOccupied) {
		t.Fatal(e)
	}
	if e := r.s.Close(); e != nil {
		t.Fatal(e)
	}
	if e := WithEmptyRegistry(context.Background(), root, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
}

func TestRegistryBarrierRefusesLockHazardsWithoutChangingThem(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "contents", "public-mode", "writable-parent"} {
		t.Run(kind, func(t *testing.T) {
			root := initializedRegistry(t)
			lock := filepath.Join(root, ".registry-lock")
			if kind != "writable-parent" {
				if e := os.Remove(lock); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "symlink":
				os.WriteFile(filepath.Join(root, "target"), nil, 0600)
				os.Symlink("target", lock)
			case "hardlink":
				os.WriteFile(filepath.Join(root, "target"), nil, 0600)
				os.Link(filepath.Join(root, "target"), lock)
			case "fifo":
				if e := syscall.Mkfifo(lock, 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				os.Mkdir(lock, 0700)
			case "contents":
				os.WriteFile(lock, []byte("unknown"), 0600)
			case "public-mode":
				os.WriteFile(lock, nil, 0644)
			case "writable-parent":
				os.Chmod(filepath.Dir(root), 0777)
				defer os.Chmod(filepath.Dir(root), 0700)
			}
			before, e := os.Lstat(lock)
			if e != nil {
				t.Fatal(e)
			}
			if e = WithEmptyRegistry(context.Background(), root, func() error { t.Fatal("invalid lock accepted"); return nil }); e == nil {
				t.Fatal("unknown lock accepted")
			}
			after, e := os.Lstat(lock)
			if e != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("observer repaired/replaced lock")
			}
		})
	}
}

func TestBindRefusesSubstitutedWorkspaceBeforeJournalWrite(t *testing.T) {
	for _, target := range []string{"registry", "workspace", "lease"} {
		t.Run(target, func(t *testing.T) {
			root := initializedRegistry(t)
			s, e := Begin(root)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Preserve()
			replace := root
			mode := os.FileMode(0700)
			if target == "workspace" {
				replace = s.Path
			}
			if target == "lease" {
				replace = filepath.Join(s.Path, "lease")
				mode = 0600
			}
			if e = os.Rename(replace, replace+"-original"); e != nil {
				t.Fatal(e)
			}
			if target == "lease" {
				e = os.WriteFile(replace, nil, mode)
			} else {
				e = os.Mkdir(replace, mode)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = s.Bind("aegis-scan-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); e == nil {
				t.Fatal("substituted workspace accepted")
			}
			if s.record.Container != "" {
				t.Fatal("binding changed on identity refusal")
			}
			if target != "lease" {
				entries, e := os.ReadDir(replace)
				if e != nil || len(entries) != 0 {
					t.Fatal("replacement directory modified", e)
				}
			}
		})
	}
}
