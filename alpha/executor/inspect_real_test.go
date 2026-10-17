// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package executor

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This explicit fixture creates a stopped container but never starts a tool.
// Only its exact random name is removed, using the original selected engine.
func TestRealOwnedSandboxObservationMatchesAndNeverReleases(t *testing.T) {
	if os.Getenv("AEGIS_REAL_SCANNER_TEST") != "1" {
		t.Skip("explicit owned Docker metadata fixture only")
	}
	host, contextName := os.Getenv("DOCKER_HOST"), os.Getenv("DOCKER_CONTEXT")
	cfg, x, a, _ := sandboxObservationFixture(t)
	t.Setenv("DOCKER_HOST", host)
	t.Setenv("DOCKER_CONTEXT", contextName)
	cfg.Docker = "docker"
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	docker, endpoint, e := cfg.engine(ctx)
	if e != nil {
		t.Fatal("original local engine unavailable")
	}
	info, e := inspectOutput(ctx, docker, endpoint, 512, "info", "--format", "{{.OSType}} {{.Architecture}} {{.ID}}")
	fields := strings.Fields(string(info))
	if e != nil || len(fields) != 3 || fields[0] != "linux" {
		t.Fatal("Linux fixture engine unavailable")
	}
	arch := fields[1]
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	sourceRoot, _ := filepath.Abs("../..")
	guard, e := os.ReadFile(filepath.Join(sourceRoot, "bin/scanner-guard-linux-"+arch))
	if e != nil {
		t.Fatal("build native research guards first")
	}
	amd, e := os.ReadFile(filepath.Join(sourceRoot, "bin/scanner-guard-linux-amd64"))
	if e != nil {
		t.Fatal(e)
	}
	arm, e := os.ReadFile(filepath.Join(sourceRoot, "bin/scanner-guard-linux-arm64"))
	if e != nil {
		t.Fatal(e)
	}
	guards, e := scanevidence.NewGuardSet(source.Hash(amd), source.Hash(arm))
	if e != nil {
		t.Fatal(e)
	}
	guardPath := filepath.Join(a.Mounts[1].Source, "scanner-guard")
	os.Chmod(guardPath, 0700)
	if e = os.WriteFile(guardPath, guard, 0500); e != nil {
		t.Fatal(e)
	}
	os.Chmod(guardPath, 0500)
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	d := x.Launch.Document
	d.Plan.Container = "aegis-scan-" + hex.EncodeToString(nonce)
	d.Plan.Engine = source.Hash([]byte(endpoint + "\n" + fields[2]))
	d.Plan.Architecture = arch
	d.Plan.Guard = source.Hash(guard)
	d.GuardSet = guards.Digest
	b, _ := json.Marshal(d)
	x.Launch = scanevidence.LaunchRecord{Digest: source.Hash(b), Document: d}
	tool, _, e := resolve(cfg.LockPath, d.Plan.Tool)
	if e != nil {
		t.Fatal(e)
	}
	name := d.Plan.Container
	uid, gid := strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid())
	args := []string{"create", "--entrypoint", "/aegis/scanner-guard", "--name", name, "--label", "io.aegis.scan=" + name, "--rm", "--pull=never", "--network=none", "--read-only", "--user=" + uid + ":" + gid, "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=768m", "--memory-swap=768m", "--cpus=1", "--log-driver=none", "--tmpfs", "/tmp:rw,noexec,nosuid,size=96m,uid=" + uid + ",gid=" + gid, "--mount", "type=bind,src=" + a.Mounts[0].Source + ",dst=/src,readonly", "--mount", "type=bind,src=" + a.Mounts[1].Source + ",dst=/aegis,readonly", tool.Image, d.Plan.Tool, "120", d.Deadline}
	created := false
	t.Cleanup(func() {
		if !created {
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if e := engineCommand(cleanup, docker, endpoint, "rm", "--force", "--volumes", name).Run(); e != nil {
			t.Error("owned fixture removal unconfirmed")
		}
	})
	if _, e = inspectOutput(ctx, docker, endpoint, 256, args...); e != nil {
		t.Fatal("owned stopped-container fixture creation refused")
	}
	created = true
	got, e := cfg.InspectSandbox(ctx, x)
	if e != nil {
		t.Fatal("real sandbox observation failed", got.Code)
	}
	if got.State != "created" || !got.MetadataMatched || !got.GuardMatched || !got.SourceMatched || got.CleanupConfirmed || got.AuthorityVerified || got.LateStartExcluded || got.LeaseExcluded {
		t.Fatal(got)
	}
	encoded, _ := json.Marshal(got)
	t.Logf("REAL_SANDBOX_OBSERVATION %s", encoded)
	// Invoke the actual operator CLI on the same private context. It must not
	// expose private paths or convert a matching observation into authority.
	parent := filepath.Dir(x.Registry)
	private := filepath.Join(parent, "private-context")
	os.Mkdir(private, 0700)
	planPath := filepath.Join(private, "launch.json")
	plan, _ := json.Marshal(x.Launch)
	os.WriteFile(planPath, plan, 0600)
	cmd := exec.CommandContext(ctx, filepath.Join(sourceRoot, "bin/aegis-research"), "observe-sandbox", planPath, x.Registry, sourceRoot)
	output, e := cmd.Output()
	if e != nil {
		t.Fatal("operator observation CLI failed")
	}
	var cli SandboxObservation
	if json.Unmarshal(output, &cli) != nil || cli.Code != "MATCHED_AT_OBSERVATION" || cli.CleanupConfirmed || cli.AuthorityVerified {
		t.Fatal("CLI observation weakened scope")
	}
	t.Logf("REAL_SANDBOX_CLI_OBSERVATION %s", output)
	// The guard path is checked independently of the supplied launch/worker
	// metadata. Deliberately change only this owned fixture file.
	os.Chmod(guardPath, 0700)
	os.WriteFile(guardPath, []byte("changed fixture"), 0500)
	os.Chmod(guardPath, 0500)
	refused, e := cfg.InspectSandbox(ctx, x)
	if e == nil || refused.Code != "GUARD_FILE_MISMATCH" || refused.CleanupConfirmed {
		t.Fatal("changed reported guard accepted", refused, e)
	}
	encoded, _ = json.Marshal(refused)
	t.Logf("REAL_SANDBOX_REFUSAL %s", encoded)
	os.Chmod(guardPath, 0700)
	os.WriteFile(guardPath, guard, 0500)
	os.Chmod(guardPath, 0500)
	if e = engineCommand(ctx, docker, endpoint, "rm", "--force", "--volumes", name).Run(); e != nil {
		t.Fatal("owned fixture removal refused")
	}
	created = false
	absent, e := cfg.InspectSandbox(ctx, x)
	if e != nil || absent.State != "absent" || absent.MetadataMatched || absent.GuardMatched || absent.CleanupConfirmed || absent.LateStartExcluded {
		t.Fatal("absence became cleanup proof", absent, e)
	}
	encoded, _ = json.Marshal(absent)
	t.Logf("REAL_SANDBOX_ABSENCE %s", encoded)
	for i, arg := range args {
		if strings.HasPrefix(arg, "--user=") {
			args[i] = "--user=0:0"
		}
	}
	if _, e = inspectOutput(ctx, docker, endpoint, 256, args...); e != nil {
		t.Fatal("owned negative fixture creation refused")
	}
	created = true
	refused, e = cfg.InspectSandbox(ctx, x)
	if e == nil || refused.Code != "SANDBOX_METADATA_MISMATCH" || refused.CleanupConfirmed {
		t.Fatal("root-user metadata accepted", refused, e)
	}
	encoded, _ = json.Marshal(refused)
	t.Logf("REAL_SANDBOX_REFUSAL %s", encoded)

}
