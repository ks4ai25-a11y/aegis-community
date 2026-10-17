// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"aegis.local/source"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutputLimitCancelsAndNeverRetainsOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &cappedOutput{limit: 4, cancel: cancel}
	if _, e := w.Write([]byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Write([]byte("private overflow")); e == nil {
		t.Fatal("overflow accepted")
	}
	bytes, exceeded := w.Bytes()
	if !exceeded || string(bytes) != "1234" || ctx.Err() == nil {
		t.Fatal("overflow not contained")
	}
}
func TestLockRequiresUniqueImmutableImages(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock.json")
	for _, data := range []string{`{"schema_version":"1.0","tools":[{"id":"semgrep_ce","version":"test","image":"semgrep/semgrep:latest"}]}`, `{"schema_version":"1.0","tools":[]}`, `not json`} {
		os.WriteFile(p, []byte(data), 0600)
		if _, _, e := resolve(p, "semgrep_ce"); e == nil {
			t.Fatal("invalid pin accepted")
		}
	}
}

func TestAuthorizedLockMismatchRefusesBeforeExecution(t *testing.T) {
	c := Config{LockPath: "../../tools/scanners.lock.json", ExpectedLockDigest: "sha256:wrong"}
	r, e := c.Run(context.Background(), "bandit", "app_demo", "repository", source.Snapshot{})
	if e == nil || r.Container != "" || r.Schema != "" {
		t.Fatal("changed lock reached execution", r, e)
	}
}

func TestLocalEngineRefusesRemoteEndpoints(t *testing.T) {
	for _, endpoint := range []string{"tcp://127.0.0.1:2375", "ssh://operator@host", "unix://host/socket", "unix:///tmp/docker.sock?x=1", "unix:///tmp/docker.sock#x", "unix:relative", "unix:///tmp/socket\n"} {
		if _, e := localEndpoint(endpoint); e == nil {
			t.Fatalf("remote or malformed endpoint accepted: %q", endpoint)
		}
	}
	if got, e := localEndpoint("unix:///tmp/docker.sock"); e != nil || got != "unix:///tmp/docker.sock" {
		t.Fatal(got, e)
	}
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
	t.Setenv("DOCKER_CONTEXT", "")
	if _, _, e := (Config{Docker: "must-not-be-executed"}).engine(context.Background()); e == nil {
		t.Fatal("remote endpoint reached engine")
	}
}

func syntheticExecutorFixture(t *testing.T) (Config, source.Snapshot) {
	t.Helper()
	t.Setenv("DOCKER_HOST", "unix:///tmp/aegis-test-only.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	repo := filepath.Join(parent, "repo")
	os.Mkdir(repo, 0700)
	os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{"name":"synthetic"}`), 0600)
	root, e := os.OpenRoot(repo)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	m, e := source.ReadRootContext(context.Background(), root, "app", "test-repository")
	if e != nil {
		t.Fatal(e)
	}
	scratch := filepath.Join(parent, "scratch")
	os.Mkdir(scratch, 0700)
	snapshot, e := source.Capture(context.Background(), root, m, scratch)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { snapshot.Close() })
	lock := filepath.Join(parent, "lock.json")
	os.WriteFile(lock, []byte(`{"schema_version":"1.0","tools":[{"id":"syft","version":"test","image":"anchore/syft@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}`), 0600)
	guard := filepath.Join(parent, "guard")
	os.Mkdir(guard, 0700)
	os.WriteFile(filepath.Join(guard, "scanner-guard-linux-arm64"), []byte("synthetic-test-guard-not-executed"), 0500)
	t.Setenv("AEGIS_TEST_ARGV_LOG", filepath.Join(parent, "argv"))
	docker := filepath.Join(parent, "fake-docker")
	os.WriteFile(docker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$AEGIS_TEST_ARGV_LOG\"\ncase \"$3\" in\n info) echo 'linux arm64 synthetic-engine';;\n run) echo '{\"specVersion\":\"1.7\",\"components\":[]}' ;;\n *) exit 1;;\nesac\n"), 0700)

	return Config{Docker: docker, GuardDir: guard, LockPath: lock, ScratchParent: scratch}, snapshot
}

func TestUnconfirmedContainerCleanupPreservesPrivateWorkspace(t *testing.T) {
	cfg, snapshot := syntheticExecutorFixture(t)
	result, e := cfg.Run(context.Background(), "syft", "app", "repository", snapshot)
	if e == nil || result.Cleanup != "unconfirmed" || result.Status != "tool_error" || result.Container == "" {
		t.Fatalf("uncertain cleanup became success: %+v %v", result, e)
	}
	entries, e := os.ReadDir(cfg.ScratchParent)
	if e != nil {
		t.Fatal(e)
	}
	preserved := false
	for _, entry := range entries {
		if len(entry.Name()) > 12 && entry.Name()[:12] == "aegis-guard-" {
			preserved = true
		}
	}
	if !preserved {
		t.Fatal("guard evidence deleted before container absence confirmed")
	}
}

func TestExpiredAbsoluteDeadlineRefusesBeforeAnyDockerOperation(t *testing.T) {
	for _, deadline := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(16 * time.Minute)} {
		r, e := (Config{Deadline: deadline, Docker: "must-not-be-executed", LockPath: "must-not-be-read"}).Run(context.Background(), "bandit", "app_demo", "repository", source.Snapshot{})
		if e == nil || r.Container != "" || r.Schema != "" {
			t.Fatal("invalid deadline reached source or Docker", r, e)
		}
	}
}

func TestDeadlineExpiresDuringAuthorizationBeforeDockerRun(t *testing.T) {
	cfg, snapshot := syntheticExecutorFixture(t)
	cfg.Deadline = time.Now().Add(2 * time.Second)
	called := false
	cfg.BeforeLaunch = func(Execution, string, string) error {
		called = true
		time.Sleep(time.Until(cfg.Deadline) + time.Millisecond)
		return nil
	}
	r, e := cfg.Run(context.Background(), "syft", "app", "repository", snapshot)
	if !called || e == nil || r.Container != "" {
		t.Fatal("expired authorization sent Docker run", r, e)
	}
	b, e := os.ReadFile(os.Getenv("AEGIS_TEST_ARGV_LOG"))
	if e != nil {
		t.Fatal(e)
	}
	for _, arg := range strings.Split(string(b), "\n") {
		if arg == "run" {
			t.Fatal("Docker start attempted after expiry")
		}
	}
	entries, e := os.ReadDir(cfg.ScratchParent)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "aegis-guard-") {
			t.Fatal("unlaunched guard workspace retained")
		}
	}
}
