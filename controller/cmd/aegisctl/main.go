// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/controller/internal/diagnostics"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/evidence"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/scantransport"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: aegisctl scanner-engine bind ENGINE_DIGEST REGISTRY_DIGEST | scanner-engine bind-journal JOURNAL_ROOT_DIGEST JOURNAL_NAMESPACE_DIGEST | scanner-engine bind-broker WORKER_ID | --version | init | doctor | diagnostics [--json] | policy validate FILE | audit verify | backup create ABSOLUTE_FILE [--json] | report verify FILE | scanner-worker enroll ID MINUTES FILE | scanner-worker revoke ID | scanner-worker probe CREDENTIAL_FILE | scanner-launch export JOB TOOL ABSOLUTE_PRIVATE_FILE | scanner-verifier enroll ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST PRIVATE_FILE | scanner-verifier revoke ID | scanner-verifier probe PRIVATE_FILE | scanner-authorizer enroll ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST POLICY_DIGEST PRIVATE_FILE | scanner-authorizer revoke ID | scanner-authorizer probe PRIVATE_FILE | scanner-reconciler enroll ID MINUTES BINDING_DIGEST PRIVATE_FILE | scanner-reconciler revoke ID | scanner-reconciler probe PRIVATE_FILE")
	}
	args := os.Args[1:]
	root := os.Getenv("AEGIS_DATA")
	if root == "" {
		root = "/var/lib/aegis"
	}
	switch args[0] {
	case "scanner-engine":
		if !(len(args) == 4 && (args[1] == "bind" || args[1] == "bind-journal") || len(args) == 3 && args[1] == "bind-broker") {
			die("usage: scanner-engine bind ENGINE_DIGEST REGISTRY_DIGEST | scanner-engine bind-journal JOURNAL_ROOT_DIGEST JOURNAL_NAMESPACE_DIGEST | scanner-engine bind-broker WORKER_ID")
		}
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die("Scanner state unavailable")
		}
		defer s.DB.Close()
		owner, e := s.Get("repository_mount_owner")
		if e != nil {
			die("Connect an owned repository before engine binding")
		}
		if args[1] == "bind-broker" {
			bound, e := (&scanqueue.Queue{S: s}).BindBroker(owner, args[2])
			if e != nil {
				die("Immutable scanner broker binding refused; cleanup admission unchanged")
			}
			json.NewEncoder(os.Stdout).Encode(bound)
			break
		}
		if args[1] == "bind-journal" {
			bound, e := (&scanqueue.Queue{S: s}).BindJournal(owner, args[2], args[3])
			if e != nil {
				die("Immutable scanner journal binding refused; cleanup admission unchanged")
			}
			json.NewEncoder(os.Stdout).Encode(bound)
			break
		}
		bound, e := (&scanqueue.Queue{S: s}).BindEngine(owner, args[2], args[3])
		if e != nil {
			die("Immutable scanner engine binding refused; cleanup admission unchanged")
		}
		json.NewEncoder(os.Stdout).Encode(bound)

	case "scanner-launch":
		if len(args) != 5 || args[1] != "export" {
			die("usage: scanner-launch export JOB_ID TOOL_ID ABSOLUTE_PRIVATE_FILE")
		}
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die("Scanner state unavailable")
		}
		defer s.DB.Close()
		owner, e := s.Get("repository_mount_owner")
		if e != nil {
			die("Owned repository mount is not provisioned")
		}
		digest, e := (&scanqueue.Queue{S: s}).ExportLaunchFile(owner, args[2], args[3], args[4])
		if e != nil {
			die("Launch context export refused")
		}
		fmt.Printf("Private launch context exported: %s; this is not cleanup authority\n", digest)
	case "--version":
		fmt.Println(domain.Version)
	case "init":
		os.MkdirAll(root, 0700)
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die(e.Error())
		}
		defer s.DB.Close()
		p, _, e := s.Active()
		if e != nil {
			die(e.Error())
		}
		socket := os.Getenv("GATEWAY_SOCKET")
		if socket == "" {
			socket = "/run/gateway/admin.sock"
		}
		log := os.Getenv("GATEWAY_LOG")
		if log == "" {
			log = "/var/log/aegis/events.jsonl"
		}
		if e = policy.Atomic(filepath.Join(configRoot(root), "active.Caddyfile"), []byte(policy.Render(p, "demo-origin:8080", ":8080", socket, log))); e != nil {
			die(e.Error())
		}
		fmt.Println("Initialized persisted policy configuration")
	case "scanner-authorizer":
		runScannerAuthorizer(root, args)
	case "scanner-reconciler":
		runScannerReconciler(root, args)
	case "scanner-verifier":
		if len(args) == 3 && args[1] == "probe" {
			socket := os.Getenv("AEGIS_SCANNER_SOCKET")
			if socket == "" {
				die("Private scanner socket is not configured")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			v, e := scantransport.ProbeVerifier(ctx, socket, args[2])
			if e != nil {
				die("Verifier probe refused")
			}
			fmt.Printf("Verifier %s authenticated for owner %s until %s; controller metadata only\n", v.ID, v.Owner, v.Expires)
			break
		}
		if len(args) < 3 || (args[1] != "enroll" && args[1] != "revoke") {
			die("usage: scanner-verifier enroll ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST PRIVATE_FILE | scanner-verifier revoke ID | scanner-verifier probe PRIVATE_FILE")
		}
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die("Verifier state unavailable")
		}
		defer s.DB.Close()
		owner, e := s.Get("repository_mount_owner")
		if e != nil {
			die("Connect an owned provisioned repository before verifier enrollment")
		}
		registry := &scannerauth.Registry{S: s}
		if args[1] == "revoke" {
			if len(args) != 3 {
				die("usage: scanner-verifier revoke ID")
			}
			if e = registry.RevokeVerifier(owner, args[2]); e != nil {
				die("Verifier revocation refused")
			}
			fmt.Println("Verifier revoked; cleanup admission remains held")
			break
		}
		if len(args) != 7 {
			die("usage: scanner-verifier enroll ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST PRIVATE_FILE")
		}
		minutes, e := strconv.Atoi(args[3])
		if e != nil {
			die("Verifier lifetime must be 1–1440 minutes")
		}
		v, e := registry.EnrollVerifierFile(owner, args[2], minutes, args[4], args[5], args[6])
		if e != nil {
			die("Verifier enrollment refused")
		}
		fmt.Printf("Verifier %s enrolled for owner %s until %s; credential written privately; controller metadata only\n", v.ID, v.Owner, v.Expires)
	case "scanner-worker":
		if len(args) == 3 && args[1] == "probe" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			socket := os.Getenv("AEGIS_SCANNER_SOCKET")
			if socket == "" {
				die("Private scanner socket is not configured")
			}
			worker, e := scantransport.Probe(ctx, socket, args[2])
			if e != nil {
				die(e.Error())
			}
			fmt.Printf("Worker %s authenticated for owner %s until %s\n", worker.ID, worker.Owner, worker.Expires)
			break
		}
		if len(args) < 3 || (args[1] != "enroll" && args[1] != "revoke") {
			die("usage: scanner-worker enroll ID MINUTES ABSOLUTE_CREDENTIAL_FILE | scanner-worker revoke ID")
		}
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die("Worker state unavailable")
		}
		defer s.DB.Close()
		owner, e := s.Get("repository_mount_owner")
		if e != nil {
			die("Connect an owned provisioned repository before worker enrollment")
		}
		registry := &scannerauth.Registry{S: s}
		if args[1] == "revoke" {
			if len(args) != 3 {
				die("usage: scanner-worker revoke ID")
			}
			if e = registry.Revoke(owner, args[2]); e != nil {
				die("Worker revocation failed")
			}
			fmt.Println("Worker revoked; running cancellation requested and cleanup admission retained")
			break
		}
		if len(args) != 5 {
			die("usage: scanner-worker enroll ID MINUTES ABSOLUTE_CREDENTIAL_FILE")
		}
		minutes, e := strconv.Atoi(args[3])
		if e != nil {
			die("Worker lifetime must be 1–1440 minutes")
		}
		worker, e := registry.EnrollFile(owner, args[2], minutes, args[4])
		if e != nil {
			die(e.Error())
		}
		fmt.Printf("Worker %s enrolled for owner %s until %s; credential written privately\n", worker.ID, worker.Owner, worker.Expires)
	case "diagnostics":
		if len(args) > 2 || (len(args) == 2 && args[1] != "--json") {
			die("usage: diagnostics [--json]")
		}
		s, e := store.OpenSnapshotSource(context.Background(), filepath.Join(root, "aegis.db"))
		if e != nil {
			die("database unavailable for read-only diagnostics: " + e.Error())
		}
		defer s.DB.Close()
		b := diagnostics.Collect(s)
		if len(args) == 2 {
			json.NewEncoder(os.Stdout).Encode(b)
			return
		}
		out, _ := json.MarshalIndent(b, "", "  ")
		fmt.Println(string(out))
		fmt.Fprintln(os.Stderr, "Contains versions, health, counters and counts only; excluded: "+strings.Join(diagnostics.Excluded, ", ")+".")
	case "doctor":
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die(e.Error())
		}
		defer s.DB.Close()
		var result string
		if e = s.DB.QueryRow("PRAGMA integrity_check").Scan(&result); e != nil || result != "ok" {
			die("SQLite integrity check failed")
		}
		p, d, e := s.Active()
		if e != nil {
			die(e.Error())
		}
		fmt.Printf("SQLite: ok\nPolicy: %s\nMode: %s\n", d, p.Mode)
		if e = s.VerifyAudit(); e != nil {
			die(e.Error())
		}
		fmt.Println("Audit chain: internally consistent; host-admin trust limitation applies")
	case "policy":
		if len(args) != 3 || args[1] != "validate" {
			die("usage: policy validate FILE")
		}
		b, e := os.ReadFile(args[2])
		if e != nil {
			die(e.Error())
		}
		var p domain.Policy
		if e = json.Unmarshal(b, &p); e != nil {
			die(e.Error())
		}
		if e = policy.Validate(p); e != nil {
			die(e.Error())
		}
		fmt.Println(domain.Digest(p))
	case "audit":
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die(e.Error())
		}
		defer s.DB.Close()
		if e = s.VerifyAudit(); e != nil {
			die(e.Error())
		}
		fmt.Println("Audit chain consistent under local-host trust assumptions")
	case "backup":
		if handleRecovery(args[1:], root) {
			break
		}
		if len(args) == 2 && args[1] == "--help" {
			fmt.Println("usage: aegisctl backup create ABSOLUTE_FILE [--json] | " + recoveryUsage + "\nCreates a private controller database snapshot in an existing directory owned by this operator. The directory must not permit group/other writes. Existing targets are refused. This snapshot does not include gateway configuration or tool manifests; restore verification remains pending. Legacy backup ABSOLUTE_FILE is also accepted.")
			break
		}
		path, jsonOutput, e := backupArguments(args[1:])
		if e != nil {
			die("usage: backup create ABSOLUTE_FILE [--json]")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, e := store.OpenSnapshotSource(ctx, filepath.Join(root, "aegis.db"))
		if e != nil {
			die("Existing recognized controller state is required; snapshot creation never initializes or migrates its source")
		}
		defer s.DB.Close()
		receipt, e := s.BackupSnapshot(ctx, path)
		if e != nil {
			die("Private database snapshot refused or incomplete; use a new absolute path in an owned directory without group/other write permission")
		}
		if jsonOutput {
			json.NewEncoder(os.Stdout).Encode(receipt)
		} else {
			fmt.Printf("Private controller database snapshot created: %s (%d bytes); restore verification remains pending\n", receipt.Digest, receipt.Bytes)
		}
	case "report":
		if (len(args) != 3 && !(len(args) == 5 && args[3] == "--key")) || args[1] != "verify" {
			die("usage: report verify FILE [--key KEY_ID_OR_PUBLIC_KEY]")
		}
		b, e := os.ReadFile(args[2])
		if e != nil {
			die(e.Error())
		}
		var env evidence.Envelope
		if json.Unmarshal(b, &env) == nil && env.Scheme != "" {
			trusted := ""
			if len(args) == 5 {
				trusted = args[4]
			}
			if e = evidence.Verify(env, evidence.ReportDigest, trusted); e != nil {
				die("Signed evidence rejected: " + e.Error())
			}
			if trusted == "" {
				fmt.Println("Signature and report identity verified for key " + env.KeyID + " (not pinned; pass --key to require a specific installation)")
			} else {
				fmt.Println("Signature and report identity verified for pinned key " + env.KeyID)
			}
			return
		}
		var r domain.Report
		if e = json.Unmarshal(b, &r); e != nil {
			die(e.Error())
		}
		d := r.Digest
		r.Digest = ""
		if domain.Digest(r) != d {
			die("Report digest mismatch")
		}
		fmt.Println("Report byte identity verified")
	default:
		die("unsupported command")
	}
}
func die(s string) { fmt.Fprintln(os.Stderr, s); os.Exit(1) }

func configRoot(fallback string) string {
	if r := os.Getenv("GATEWAY_POLICY_ROOT"); r != "" {
		return r
	}
	return fallback
}

func backupArguments(args []string) (string, bool, error) {
	jsonOutput := false
	if len(args) > 0 && args[len(args)-1] == "--json" {
		jsonOutput = true
		args = args[:len(args)-1]
	}
	if len(args) == 2 && args[0] == "create" {
		args = args[1:]
	}
	if len(args) != 1 || !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] {
		return "", false, fmt.Errorf("invalid backup arguments")
	}
	return args[0], jsonOutput, nil
}
