// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scantransport"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: aegisctl --version | init | doctor | policy validate FILE | audit verify | backup FILE | report verify FILE | scanner-worker enroll ID MINUTES FILE | scanner-worker revoke ID | scanner-worker probe CREDENTIAL_FILE")
	}
	args := os.Args[1:]
	root := os.Getenv("AEGIS_DATA")
	if root == "" {
		root = "/var/lib/aegis"
	}
	switch args[0] {
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
		if len(args) != 2 {
			die("usage: backup FILE")
		}
		s, e := store.Open(filepath.Join(root, "aegis.db"))
		if e != nil {
			die(e.Error())
		}
		defer s.DB.Close()
		if e = s.Backup(context.Background(), args[1]); e != nil {
			die(e.Error())
		}
		fmt.Println("Consistent SQLite snapshot created; protect it as sensitive owner state")
	case "report":
		if len(args) != 3 || args[1] != "verify" {
			die("usage: report verify FILE")
		}
		b, e := os.ReadFile(args[2])
		if e != nil {
			die(e.Error())
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
