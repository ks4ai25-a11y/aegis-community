//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"aegis.local/source"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// No source or manifest is mounted: exit 124 proves expiration was checked
// before even reading source, while malformed time must refuse with exit 125.
func TestRealGuardAbsoluteDeadlineRefusesBeforeSourceOrScanner(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker guard acceptance only")
	}
	cfg := Config{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docker, endpoint, e := cfg.engine(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := engineCommand(ctx, docker, endpoint, "info", "--format", "{{.OSType}} {{.Architecture}} {{.ID}}").Output()
	fields := strings.Fields(string(raw))
	if e != nil || len(fields) != 3 || fields[0] != "linux" {
		t.Fatal("supported local Linux engine required")
	}
	arch := fields[1]
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	if arch != "arm64" && arch != "amd64" {
		t.Fatal("unsupported guard architecture")
	}
	guard, e := os.ReadFile("../../bin/scanner-guard-linux-" + arch)
	if e != nil {
		t.Fatal(e)
	}
	parent, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(parent, "scanner-guard"), guard, 0500); e != nil {
		t.Fatal(e)
	}
	tool, _, e := resolve("../../tools/scanners.lock.json", "bandit")
	if e != nil {
		t.Fatal(e)
	}
	engine := source.Hash([]byte(endpoint + "\n" + fields[2]))
	for _, probe := range []struct {
		name, deadline string
		exit           int
	}{{"expired", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), 124}, {"malformed", "not-a-deadline", 125}} {
		t.Run(probe.name, func(t *testing.T) {
			nonce := make([]byte, 16)
			if _, e := rand.Read(nonce); e != nil {
				t.Fatal(e)
			}
			name := "aegis-scan-" + hex.EncodeToString(nonce)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				_ = engineCommand(cleanup, docker, endpoint, "rm", "--force", "--volumes", name).Run()
				absent, e := cfg.ContainerAbsent(cleanup, name, engine)
				if e != nil || !absent {
					t.Fatal("owned guard container absence unconfirmed", e)
				}
			}()
			args := []string{"run", "--rm", "--pull=never", "--name", name, "--label", "io.aegis.scan=" + name, "--entrypoint", "/aegis/scanner-guard", "--network=none", "--read-only", "--user", strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid()), "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=768m", "--memory-swap=768m", "--cpus=1", "--log-driver=none", "--mount", "type=bind,src=" + parent + ",dst=/aegis,readonly", tool.Image, "bandit", "120", probe.deadline}
			command := engineCommand(ctx, docker, endpoint, args...)
			output, e := command.CombinedOutput()
			if e == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != probe.exit || len(output) != 0 {
				t.Fatal("guard failed to reject before source read", command.ProcessState, e)
			}
			record := map[string]any{"case": probe.name, "exit_code": probe.exit, "guard_binary_digest": source.Hash(guard), "image": tool.Image, "container": name, "source_mounted": false}
			b, _ := json.Marshal(record)
			t.Logf("GUARD_DEADLINE_PROBE %s", b)
		})
	}
}
