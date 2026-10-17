// SPDX-License-Identifier: BUSL-1.1
// aegis-scanner-db provisions and verifies offline OSV and Trivy databases.
//
//	aegis-scanner-db fetch ROOT [--tools osv_v2,trivy] [--ecosystems npm,PyPI] [--lock tools/scanners.lock.json]
//	aegis-scanner-db verify ROOT [--max-age 168h] [--json]
//
// fetch is the only step with network access; it uses free public sources and the
// digest-pinned Trivy image. Scanner jobs receive the verified tree read-only.
package main

import (
	"aegis.local/alpha/scannerdb"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func die(msg string) { fmt.Fprintln(os.Stderr, "aegis-scanner-db:", msg); os.Exit(1) }

func trivyImage(lock string) string {
	b, e := os.ReadFile(lock)
	if e != nil {
		die("cannot read tool lock: " + e.Error())
	}
	var l struct {
		Tools []struct{ ID, Image string } `json:"tools"`
	}
	if json.Unmarshal(b, &l) != nil {
		die("invalid tool lock")
	}
	for _, t := range l.Tools {
		if t.ID == "trivy" {
			return t.Image
		}
	}
	die("tool lock has no trivy entry")
	return ""
}

func main() {
	if len(os.Args) < 3 || (os.Args[1] != "fetch" && os.Args[1] != "verify") {
		die("usage: fetch ROOT [--tools osv_v2,trivy] [--ecosystems LIST] [--lock FILE] | verify ROOT [--max-age 168h] [--json]")
	}
	cmd, root := os.Args[1], os.Args[2]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	tools := fs.String("tools", "osv_v2,trivy", "databases to fetch")
	ecos := fs.String("ecosystems", strings.Join(scannerdb.DefaultEcosystems, ","), "OSV ecosystems")
	lock := fs.String("lock", "tools/scanners.lock.json", "pinned tool lock")
	maxAge := fs.Duration("max-age", 7*24*time.Hour, "age after which a database is reported stale")
	asJSON := fs.Bool("json", false, "machine-readable output")
	fs.Parse(os.Args[3:])
	if e := os.MkdirAll(root, 0755); e != nil {
		die(e.Error())
	}
	switch cmd {
	case "fetch":
		ctx := context.Background()
		for _, tool := range strings.Split(*tools, ",") {
			var db scannerdb.Database
			var e error
			switch tool {
			case "osv_v2":
				fmt.Println("Downloading OSV advisories for", *ecos, "…")
				db, e = scannerdb.FetchOSV(ctx, root, strings.Split(*ecos, ","), nil)
			case "trivy":
				fmt.Println("Downloading the Trivy database with the pinned image …")
				db, e = scannerdb.FetchTrivy(ctx, root, trivyImage(*lock))
			default:
				die("unknown tool " + tool)
			}
			if e != nil {
				die(e.Error())
			}
			if _, e = scannerdb.WriteManifest(root, db); e != nil {
				die(e.Error())
			}
			fmt.Printf("%s: %d files, %s, built %s\n", db.Tool, len(db.Files), db.Digest[:19], db.BuiltAt)
		}
	case "verify":
		st, e := scannerdb.Verify(root, *maxAge, time.Now())
		if e != nil {
			die(e.Error())
		}
		if *asJSON {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"databases": st})
			return
		}
		for _, s := range st {
			state := "fresh"
			if s.Stale {
				state = "STALE"
			}
			fmt.Printf("%-7s %s  built %s  age %.1f h  %s\n", s.Tool, s.Digest[:19], s.BuiltAt, s.AgeHours, state)
		}
	}
}
