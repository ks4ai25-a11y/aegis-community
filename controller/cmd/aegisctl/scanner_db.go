// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/store"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// runScannerDB approves offline advisory databases fetched and verified with
// aegis-scanner-db (ADR 068). Approval records the exact digests; jobs queued
// afterwards carry them, and only scans that used those databases, while
// fresh, report current advisory coverage.
func runScannerDB(root string, args []string) {
	const usage = "usage: aegisctl scanner-db approve MANIFEST_JSON | scanner-db list | scanner-db revoke osv_v2|trivy"
	if len(args) < 2 {
		die(usage)
	}
	s, e := store.Open(filepath.Join(root, "aegis.db"))
	if e != nil {
		die("Controller database unavailable")
	}
	defer s.DB.Close()
	q := &scanqueue.Queue{S: s}
	switch {
	case args[1] == "approve" && len(args) == 3:
		b, e := os.ReadFile(args[2])
		if e != nil || len(b) > 1<<20 {
			die("Manifest unreadable")
		}
		var m struct {
			Schema    string `json:"schema_version"`
			Databases []struct {
				Tool    string `json:"tool"`
				Digest  string `json:"digest"`
				BuiltAt string `json:"upstream_built_at"`
			} `json:"databases"`
		}
		if json.Unmarshal(b, &m) != nil || m.Schema != "1.0" || len(m.Databases) == 0 {
			die("Not a ScannerDatabaseManifestV1 file; run aegis-scanner-db verify first")
		}
		for _, d := range m.Databases {
			a, e := q.ApproveDatabase("operator", d.Tool, d.Digest, d.BuiltAt)
			if e != nil {
				die("Approval refused for " + d.Tool)
			}
			fmt.Printf("Approved %s database %s (built %s). Jobs queued from now on carry this digest.\n", a.Tool, a.Digest, a.BuiltAt)
		}
	case args[1] == "list" && len(args) == 2:
		list, e := q.DatabaseApprovals()
		if e != nil {
			die("Approvals unreadable")
		}
		if len(list) == 0 {
			fmt.Println("No advisory databases approved; OSV-Scanner and Trivy results report completed_stale_db.")
		}
		for _, a := range list {
			fmt.Printf("%s\t%s\tbuilt %s\tapproved %s\n", a.Tool, a.Digest, a.BuiltAt, a.ApprovedAt)
		}
	case args[1] == "revoke" && len(args) == 3:
		if q.RevokeDatabase("operator", args[2]) != nil {
			die(usage)
		}
		fmt.Println("Revoked. Jobs already queued keep their recorded digest.")
	default:
		die(usage)
	}
}
