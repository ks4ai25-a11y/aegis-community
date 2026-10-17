// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scantransport"
	"aegis.local/controller/internal/store"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func runScannerReconciler(root string, args []string) {
	const usage = "usage: scanner-reconciler enroll ID MINUTES BINDING_DIGEST PRIVATE_FILE | scanner-reconciler revoke ID | scanner-reconciler probe PRIVATE_FILE | scanner-reconciler held"
	if len(args) == 3 && args[1] == "probe" {
		socket := os.Getenv("AEGIS_SCANNER_SOCKET")
		if socket == "" {
			die("Private scanner socket is not configured")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := scantransport.ProbeReconciler(ctx, socket, args[2]); err != nil {
			die("Reconciler probe refused")
		}
		fmt.Println("Reconciler authenticated for one retained binding; identity probe only; no cleanup confirmation recorded")
		return
	}
	if !(len(args) == 3 && args[1] == "revoke" || len(args) == 6 && args[1] == "enroll" || len(args) == 2 && args[1] == "held") {
		die(usage)
	}
	s, err := store.Open(filepath.Join(root, "aegis.db"))
	if err != nil {
		die("Reconciler state unavailable")
	}
	defer s.DB.Close()
	owner, err := s.Get("repository_mount_owner")
	if err != nil {
		die("Provision owned repositories before reconciler enrollment")
	}
	if args[1] == "held" {
		// The job and generation an operator passes to reconcile-cleanup.
		var job, generation, state, finished string
		err = s.DB.QueryRow("SELECT j.id,g.id,j.state,j.finished_at FROM scanner_dispatch d JOIN scanner_jobs j ON j.id=d.job JOIN scanner_allocation_generations g ON g.job=d.job WHERE d.state='cleanup_required' AND g.state='closed' AND j.owner=?", owner).Scan(&job, &generation, &state, &finished)
		if err == sql.ErrNoRows {
			fmt.Println("No scanner slot is held for cleanup")
			return
		}
		if err != nil {
			die("Held cleanup state unavailable")
		}
		fmt.Printf("Held for cleanup: job %s generation %s (job %s, finished %s)\n", job, generation, state, finished)
		return
	}
	r := &scannerauth.Registry{S: s}
	if args[1] == "revoke" {
		if r.RevokeReconciler(owner, args[2]) != nil {
			die("Reconciler revocation refused")
		}
		fmt.Println("Reconciler revoked; retained history and cleanup holds preserved")
		return
	}
	minutes, err := strconv.Atoi(args[3])
	if err != nil {
		die("Reconciler lifetime must be 1–1440 minutes")
	}
	if _, err = r.EnrollReconcilerFile(owner, args[2], minutes, args[4], args[5]); err != nil {
		die("Reconciler enrollment refused; retain the original binding and cleanup hold")
	}
	fmt.Println("Reconciler enrolled for one retained binding; credential written privately; release requires aegis-research reconcile-cleanup with independent absence observation")
}
