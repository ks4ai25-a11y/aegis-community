// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: aegisctl --version | init | doctor | policy validate FILE | audit verify | backup FILE | report verify FILE")
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
