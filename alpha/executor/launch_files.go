// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"os"
	"path/filepath"
	"strconv"
)

// CheckLaunchFiles checks the exact reported source, guard and optional rules
// paths against a guarded launch. It performs no engine RPC and grants no
// lease, mutation or cleanup authority. Host filesystem immutability remains a
// separate deployment requirement.
func CheckLaunchFiles(ctx context.Context, x SandboxExpectation, sourcePath, guardPath, rulesPath string) error {
	if _, e := inspectionPlan(x); e != nil {
		return e
	}
	root, e := inspectionRoot(x.Registry, 0700)
	if e != nil {
		return ErrObservation
	}
	root.Close()
	expected := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + x.Registry + "\n" + strconv.Itoa(os.Geteuid())))
	if os.Geteuid() <= 0 || expected != x.Launch.Document.Plan.Registry || (x.Launch.Document.Plan.Tool == "semgrep_ce") != (rulesPath != "") {
		return ErrObservation
	}
	_, e = checkLaunchFiles(ctx, x, map[string]string{"/src": sourcePath, "/aegis": guardPath, "/rules": rulesPath})
	return e
}

func checkLaunchFiles(ctx context.Context, x SandboxExpectation, mounts map[string]string) (out SandboxObservation, err error) {
	d, p := x.Launch.Document, x.Launch.Document.Plan
	fail := func(code string) (SandboxObservation, error) { out.Code = code; return out, ErrObservation }
	session := filepath.Join(x.Registry, p.Workspace)
	root, e := inspectionRoot(session, 0700)
	if e != nil {
		return fail("WORKSPACE_UNCONFIRMED")
	}
	root.Close()
	sourceDir, e := inspectionChild(session, mounts["/src"], "aegis-source-")
	if e != nil {
		return fail("SOURCE_MOUNT_UNCONFIRMED")
	}
	defer sourceDir.Close()
	guardDir, e := inspectionChild(session, mounts["/aegis"], "aegis-guard-")
	if e != nil {
		return fail("GUARD_MOUNT_UNCONFIRMED")
	}
	defer guardDir.Close()
	guard, e := inspectionFile(guardDir, "scanner-guard", 0500, 16<<20)
	if e != nil || source.Hash(guard) != p.Guard {
		return fail("GUARD_FILE_MISMATCH")
	}
	out.GuardMatched = true
	manifestBytes, e := inspectionFile(guardDir, "input-manifest.json", 0400, scanevidence.MaxOutput)
	if e != nil {
		return fail("SOURCE_MANIFEST_UNCONFIRMED")
	}
	var manifest source.Manifest
	if inspectionJSON(manifestBytes, &manifest, scanevidence.MaxOutput) != nil || manifest.Digest != p.Snapshot || manifest.InputMap != d.Map || source.ValidateSnapshot(ctx, sourceDir, manifest) != nil {
		return fail("SOURCE_SNAPSHOT_MISMATCH")
	}
	out.SourceMatched = true
	if p.Tool == "semgrep_ce" {
		rules, e := inspectionChild(session, mounts["/rules"], "aegis-source-")
		if e != nil {
			return fail("RULES_MOUNT_UNCONFIRMED")
		}
		defer rules.Close()
		b, e := inspectionFile(guardDir, "rules-manifest.json", 0400, scanevidence.MaxOutput)
		if e != nil {
			return fail("RULES_MANIFEST_UNCONFIRMED")
		}
		var m source.Manifest
		if inspectionJSON(b, &m, scanevidence.MaxOutput) != nil || m.Digest != x.RulesDigest || source.ValidateSnapshot(ctx, rules, m) != nil {
			return fail("RULES_SNAPSHOT_MISMATCH")
		}
		out.RulesMatched = true
	}

	if ctx.Err() != nil {
		return fail("OBSERVATION_CANCELLED")
	}
	return out, nil
}
