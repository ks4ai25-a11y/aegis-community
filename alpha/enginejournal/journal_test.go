// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package enginejournal

import (
	"aegis.local/source"
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func journalFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("non-root operator")
	}
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	return filepath.Join(parent, "journal"), source.Hash([]byte("engine"))
}
func fullAttempt(t *testing.T, j *Journal, name string) {
	t.Helper()
	a, e := j.Begin(name, source.Hash([]byte("descriptor")))
	if e != nil {
		t.Fatal(e)
	}
	container := strings.Repeat("a", 64)
	for _, op := range []string{"create", "start", "remove"} {
		in := ""
		status := 201
		if op != "create" {
			in = container
			status = 204
		}
		ticket, e := a.Begin(op, in)
		if e != nil {
			t.Fatal(e)
		}
		if e = ticket.Confirm(status, container); e != nil {
			t.Fatal(e)
		}
	}
	if e = a.Finish(); e != nil {
		t.Fatal(e)
	}
}
func TestJournalPersistsResolvedRequestsWithoutAuthorizingCleanup(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	fullAttempt(t, j, "aegis-scan-"+strings.Repeat("a", 32))
	before := j.Observe()
	j.Close()
	j, e = Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	after := j.Observe()
	if before != after || after.Attempts != 1 || after.Unresolved != 0 || after.Unfinished != 0 || after.ControllerBound || after.ExclusiveOrigin || after.CleanupAuthorized {
		t.Fatal(after)
	}
	fullAttempt(t, j, "aegis-scan-"+strings.Repeat("b", 32))
}
func TestJournalUnansweredMutationSurvivesRestartAndRefusesFurtherWrites(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	a, e := j.Begin("aegis-scan-"+strings.Repeat("c", 32), source.Hash([]byte("descriptor")))
	if e != nil {
		t.Fatal(e)
	}
	ticket, e := a.Begin("create", "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Open(path, engine); e == nil {
		t.Fatal("concurrent namespace writer")
	}
	if e = a.Finish(); !errors.Is(e, ErrPending) {
		t.Fatal("unanswered request finished", e)
	}
	j.Close()
	if e = ticket.Confirm(201, strings.Repeat("c", 64)); e == nil {
		t.Fatal("closed caller acknowledged later response")
	}
	reopened, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	state := reopened.Observe()
	if state.Unresolved != 1 || state.Unfinished != 1 || state.CleanupAuthorized {
		t.Fatal(state)
	}
	if _, e = reopened.Begin("aegis-scan-"+strings.Repeat("d", 32), source.Hash([]byte("other"))); !errors.Is(e, ErrPending) {
		t.Fatal("unresolved state bypassed", e)
	}
	if _, e = Open(path, source.Hash([]byte("other engine"))); e == nil {
		t.Fatal("engine changed")
	}
}
func TestJournalInterruptedLifecycleRemainsUnfinished(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := j.Begin("aegis-scan-"+strings.Repeat("e", 32), source.Hash([]byte("descriptor")))
	ticket, _ := a.Begin("create", "")
	if e = ticket.Confirm(201, strings.Repeat("e", 64)); e != nil {
		t.Fatal(e)
	}
	j.Close()
	j, e = Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	state := j.Observe()
	if state.Unresolved != 0 || state.Unfinished != 1 {
		t.Fatal(state)
	}
	if _, e = j.Begin("aegis-scan-"+strings.Repeat("f", 32), source.Hash([]byte("descriptor"))); !errors.Is(e, ErrPending) {
		t.Fatal("orphan lifecycle bypassed", e)
	}
}
func TestJournalRefusesUnsafeFilesystemAndTornOrUnknownRecords(t *testing.T) {
	for _, kind := range []string{"public", "symlink_root", "lock_symlink", "identity_torn", "identity_alias", "unknown", "attempt_torn", "missing_intent", "response_torn", "lock_fifo", "lock_hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path, engine := journalFixture(t)
			j, e := Open(path, engine)
			if e != nil {
				t.Fatal(e)
			}
			fullAttempt(t, j, "aegis-scan-"+strings.Repeat("a", 32))
			j.Close()
			run := filepath.Join(path, "aegis-scan-"+strings.Repeat("a", 32))
			switch kind {
			case "public":
				os.Chmod(path, 0755)
			case "symlink_root":
				real := path + "-actual"
				os.Rename(path, real)
				os.Symlink(real, path)
			case "lock_symlink":
				os.Remove(filepath.Join(path, ".lock"))
				os.Symlink("identity.json", filepath.Join(path, ".lock"))
			case "lock_fifo":
				os.Remove(filepath.Join(path, ".lock"))
				if e := syscall.Mkfifo(filepath.Join(path, ".lock"), 0600); e != nil {
					t.Fatal(e)
				}
			case "lock_hardlink":
				os.Remove(filepath.Join(path, ".lock"))
				if e := os.Link(filepath.Join(path, "identity.json"), filepath.Join(path, ".lock")); e != nil {
					t.Fatal(e)
				}
			case "identity_torn":
				os.WriteFile(filepath.Join(path, "identity.json"), []byte("{"), 0600)
			case "identity_alias":
				p := filepath.Join(path, "identity.json")
				b, _ := os.ReadFile(p)
				os.WriteFile(p, []byte(strings.Replace(string(b), "namespace_id", "Namespace_id", 1)), 0600)
			case "unknown":
				os.WriteFile(filepath.Join(path, "unknown"), []byte("x"), 0600)
			case "attempt_torn":
				os.WriteFile(filepath.Join(run, "attempt.json"), []byte("{}"), 0600)
			case "missing_intent":
				os.Remove(filepath.Join(run, "start.pending.json"))
			case "response_torn":
				os.WriteFile(filepath.Join(run, "remove.response.json"), []byte("{}"), 0600)
			}
			if opened, e := Open(path, engine); e == nil {
				opened.Close()
				t.Fatal("unsafe journal accepted", kind)
			}
		})
	}
}
func TestJournalStateMachineAndBudgetsRefuseBeforeNewRequest(t *testing.T) {
	path, engine := journalFixture(t)
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	a, _ := j.Begin("aegis-scan-"+strings.Repeat("a", 32), source.Hash([]byte("descriptor")))
	if _, e = a.Begin("start", strings.Repeat("a", 64)); e == nil {
		t.Fatal("start without create")
	}
	ticket, e := a.Begin("create", "")
	if e != nil {
		t.Fatal(e)
	}
	if e = ticket.Confirm(200, strings.Repeat("a", 64)); e == nil {
		t.Fatal("unexpected create response")
	}
	if e = ticket.Confirm(201, "short"); e == nil {
		t.Fatal("short identity accepted")
	}
	if e = ticket.Confirm(201, strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Begin("remove", strings.Repeat("b", 64)); e == nil {
		t.Fatal("unowned resource")
	}
	j.bytes = maxBytes
	if _, e = a.Begin("start", strings.Repeat("a", 64)); !errors.Is(e, ErrFull) {
		t.Fatal("byte limit", e)
	}
	if _, e = os.Stat(filepath.Join(path, a.name, "start.pending.json")); !os.IsNotExist(e) {
		t.Fatal("request intent appeared despite budget")
	}
}

func TestJournalWriterCrashKeepsPendingIntentAndReleasesKernelLock(t *testing.T) {
	if os.Getenv("AEGIS_JOURNAL_CRASH_HELPER") == "1" {
		j, e := Open(os.Getenv("AEGIS_JOURNAL_TEST_PATH"), source.Hash([]byte("engine")))
		if e != nil {
			os.Exit(10)
		}
		a, e := j.Begin("aegis-scan-"+strings.Repeat("9", 32), source.Hash([]byte("descriptor")))
		if e != nil {
			os.Exit(11)
		}
		if _, e = a.Begin("create", ""); e != nil {
			os.Exit(12)
		}
		os.Stdout.Write([]byte("ready\n"))
		// The parent kills this process without Close or any deferred cleanup.
		select {}
	}
	path, engine := journalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalWriterCrashKeepsPendingIntentAndReleasesKernelLock$")
	child.Env = append(os.Environ(), "AEGIS_JOURNAL_CRASH_HELPER=1", "AEGIS_JOURNAL_TEST_PATH="+path)
	stdout, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil || line != "ready\n" {
		t.Fatal("helper failed before durable intent")
	}
	if other, e := Open(path, engine); e == nil {
		other.Close()
		t.Fatal("live process lock bypassed")
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e = child.Wait(); e == nil {
		t.Fatal("expected crash")
	}
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal("crashed lock did not release", e)
	}
	defer j.Close()
	state := j.Observe()
	if state.Unresolved != 1 || state.Unfinished != 1 || state.CleanupAuthorized {
		t.Fatal(state)
	}
	if _, e = j.Begin("aegis-scan-"+strings.Repeat("8", 32), source.Hash([]byte("descriptor"))); !errors.Is(e, ErrPending) {
		t.Fatal("crash erased pending operation", e)
	}
}

func TestJournalObservationDoesNotCreateOrRepairMissingFiles(t *testing.T) {
	path, engine := journalFixture(t)
	if _, e := ReadObservation(path, engine); e == nil {
		t.Fatal("invented missing journal")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("observer created directory")
	}
	j, e := Open(path, engine)
	if e != nil {
		t.Fatal(e)
	}
	a, e := j.Begin("aegis-scan-"+strings.Repeat("7", 32), source.Hash([]byte("descriptor")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Begin("create", ""); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadObservation(path, engine); e == nil {
		t.Fatal("observer bypassed live writer")
	}
	expected := j.Observe()
	j.Close()
	got, e := ReadObservation(path, engine)
	if e != nil || got != expected {
		t.Fatal("observer changed pending request", e)
	}
	if e = os.Remove(filepath.Join(path, ".lock")); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadObservation(path, engine); e == nil {
		t.Fatal("missing lock repaired")
	}
	if _, e = os.Lstat(filepath.Join(path, ".lock")); !os.IsNotExist(e) {
		t.Fatal("observer recreated lock")
	}
}
