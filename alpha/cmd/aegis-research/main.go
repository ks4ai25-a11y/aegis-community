// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/alpha/executor"
	"aegis.local/alpha/inventory"
	"aegis.local/alpha/lab"
	"aegis.local/alpha/scanners"
	"aegis.local/alpha/worker"
	"aegis.local/alpha/workerchannel"
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "verifier-context":
		if len(os.Args) != 10 {
			die(fmt.Errorf("usage: aegis-research verifier-context SOCKET CREDENTIAL_FILE OWNER VERIFIER_ID ENGINE_DIGEST REGISTRY_DIGEST CANONICAL_AEGIS_SOURCE_ROOT JOB"))
		}
		root, e := filepath.EvalSymlinks(os.Args[8])
		if e != nil || root != os.Args[8] || !filepath.IsAbs(root) {
			die(fmt.Errorf("canonical source root required"))
		}
		lock, e := executor.ConfiguredToolLockDigest(filepath.Join(root, "tools/scanners.lock.json"))
		if e != nil {
			die(fmt.Errorf("trusted tool lock unavailable"))
		}
		client, e := workerchannel.NewVerifier(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7], lock)
		if e != nil {
			die(fmt.Errorf("private verifier configuration unavailable"))
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, e := client.Context(ctx, os.Args[9])
		if e != nil {
			die(e)
		}
		json.NewEncoder(os.Stdout).Encode(out)
	case "observe-sandbox":
		if len(os.Args) != 5 && len(os.Args) != 6 {
			die(fmt.Errorf("usage: aegis-research observe-sandbox PRIVATE_LAUNCH_FILE CANONICAL_REGISTRY CANONICAL_AEGIS_SOURCE_ROOT [APPROVED_RULES_DIGEST]"))
		}
		launch, e := executor.LoadObservationLaunch(os.Args[2])
		if e != nil {
			die(fmt.Errorf("private launch context unavailable"))
		}
		expected := executor.SandboxExpectation{Launch: launch, Registry: os.Args[3]}
		if len(os.Args) == 6 {
			expected.RulesDigest = os.Args[5]
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, e := (executor.Config{LockPath: filepath.Join(os.Args[4], "tools/scanners.lock.json")}).InspectSandbox(ctx, expected)
		json.NewEncoder(os.Stdout).Encode(out)
		if e != nil {
			die(e)
		}
	case "worker-once":
		if len(os.Args) != 7 {
			die(fmt.Errorf("usage: aegis-research worker-once SOCKET CREDENTIAL_FILE OWNER CANONICAL_AEGIS_SOURCE_ROOT CANONICAL_ASSET_ROOT"))
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		r, e := (worker.Config{Socket: os.Args[2], Credential: os.Args[3], Owner: os.Args[4], SourceRoot: os.Args[5], AssetRoot: os.Args[6]}).RunOnce(ctx)
		json.NewEncoder(os.Stdout).Encode(r)
		if e != nil {
			die(e)
		}
	case "recover-workspaces":
		if len(os.Args) != 2 {
			die(fmt.Errorf("recover-workspaces takes no path or container arguments"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cfg := executor.Config{}
		r, e := workspace.Recover(ctx, workspace.DefaultRoot(), time.Now(), cfg.ContainerAbsent)
		if e != nil {
			die(e)
		}
		json.NewEncoder(os.Stdout).Encode(r)
	case "scan-offline":
		if len(os.Args) != 5 {
			die(fmt.Errorf("usage: aegis-research recover-workspaces | scan-offline SCANNER CANONICAL_REPO AEGIS_SOURCE_ROOT"))
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		m, e := inventory.Read(os.Args[3], "app_demo")
		if e != nil {
			die(e)
		}
		root, e := os.OpenRoot(os.Args[3])
		if e != nil {
			die(e)
		}
		session, e := workspace.Begin(workspace.DefaultRoot())
		if e != nil {
			root.Close()
			die(e)
		}
		snapshot, e := source.Capture(ctx, root, m, session.Path)
		root.Close()
		if e != nil {
			if snapshot.Path != "" {
				snapshot.Close()
			}
			session.Close()
			die(e)
		}
		limit, e := strconv.Atoi(os.Getenv("AEGIS_SCAN_MAX_SECONDS"))
		if os.Getenv("AEGIS_SCAN_MAX_SECONDS") == "" {
			limit = 0
			e = nil
		}
		if e != nil {
			snapshot.Close()
			session.Close()
			die(fmt.Errorf("invalid scan duration"))
		}
		cfg := executor.Config{ScratchParent: session.Path, BeforeStart: session.Bind, GuardDir: filepath.Join(os.Args[4], "bin"), DurationSeconds: limit, LockPath: filepath.Join(os.Args[4], "tools/scanners.lock.json"), RulesPath: filepath.Join(os.Args[4], "alpha/rules")}
		result, runErr := cfg.Run(ctx, os.Args[2], "app_demo", "local-operator-repository", snapshot)
		if result.Container == "" || result.Cleanup == "complete" {
			if e = snapshot.Close(); e != nil {
				result.Status = "tool_error"
				result.Cleanup = "unconfirmed"
				runErr = fmt.Errorf("source cleanup unconfirmed")
			}
		}
		if result.Container == "" || result.Cleanup == "complete" {
			if e = session.Close(); e != nil {
				result.Status = "tool_error"
				result.Cleanup = "unconfirmed"
				runErr = fmt.Errorf("session cleanup unconfirmed")
			}
		} else {
			session.Preserve()
		}
		if runErr != nil && result.Container == "" {
			fmt.Fprintln(os.Stderr, "scanner preflight refused")
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(result)
		if runErr != nil {
			fmt.Fprintln(os.Stderr, "scanner execution refused or cleanup unconfirmed")
			os.Exit(1)
		}
		if result.Status == "tool_error" {
			os.Exit(1)
		}
	case "--help":
		fmt.Println("aegis-research observe-sandbox PRIVATE_LAUNCH_FILE CANONICAL_REGISTRY CANONICAL_AEGIS_SOURCE_ROOT [APPROVED_RULES_DIGEST] | worker-once SOCKET CREDENTIAL_FILE OWNER CANONICAL_AEGIS_SOURCE_ROOT CANONICAL_ASSET_ROOT | recover-workspaces | scan-offline SCANNER CANONICAL_REPO AEGIS_SOURCE_ROOT | inventory CANONICAL_REPO | invocation SCANNER | parse SCANNER VERSION IMAGE_DIGEST INPUT_DIGEST | tenant-verify VARIANT")
		return
	case "tenant-verify":
		if len(os.Args) != 3 {
			usage()
		}
		r, e := lab.VerifyTenant(os.Args[2])
		if e != nil {
			die(e)
		}
		json.NewEncoder(os.Stdout).Encode(r)
		if r.Overall != "PASS" {
			os.Exit(1)
		}
	case "parse":
		if len(os.Args) != 6 {
			usage()
		}
		b, e := io.ReadAll(io.LimitReader(os.Stdin, scanners.MaxOutput+1))
		if e != nil {
			die(e)
		}
		r, e := scanners.Parse(os.Args[2], b, scanners.Job{App: "app_demo", Repository: "bundled-scanner-fixture", ToolVersion: os.Args[3], ImageDigest: os.Args[4], InputDigest: os.Args[5], SecretSalt: []byte("synthetic-fixture-only-salt-not-production")})
		json.NewEncoder(os.Stdout).Encode(r)
		if e != nil {
			fmt.Fprintln(os.Stderr, "tool_error: invalid or unsupported bounded report")
			os.Exit(1)
		}
	case "inventory":
		if len(os.Args) != 3 {
			usage()
		}
		m, e := inventory.Read(os.Args[2], "app_demo")
		if e != nil {
			die(e)
		}
		json.NewEncoder(os.Stdout).Encode(m)
	case "invocation":
		if len(os.Args) != 3 {
			usage()
		}
		i, e := scanners.BuildInvocation(os.Args[2])
		if e != nil {
			die(e)
		}
		json.NewEncoder(os.Stdout).Encode(i)
	default:
		usage()
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: aegis-research verifier-context SOCKET CREDENTIAL_FILE OWNER VERIFIER_ID ENGINE_DIGEST REGISTRY_DIGEST CANONICAL_AEGIS_SOURCE_ROOT JOB | observe-sandbox PRIVATE_LAUNCH_FILE CANONICAL_REGISTRY CANONICAL_AEGIS_SOURCE_ROOT [APPROVED_RULES_DIGEST] | inventory CANONICAL_REPO | invocation SCANNER\nInventory never executes source. Invocation prints an unexecuted adapter blueprint; pinned compatibility validation is required.")
	os.Exit(2)
}
func die(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
