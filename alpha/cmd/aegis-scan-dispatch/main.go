// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/source/brokerwire"
	"aegis.local/source/privateipc"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "enroll" {
		if privateipc.EnrollToken(os.Args[2]) != nil {
			fmt.Fprintln(os.Stderr, "Private dispatch credential creation refused")
			os.Exit(1)
		}
		fmt.Println("Private dispatch credential created")
		return
	}
	if len(os.Args) != 4 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: aegis-scan-dispatch enroll PRIVATE_FILE | run PRIVATE_SOCKET PRIVATE_FILE")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	out, e := brokerwire.Dispatch(ctx, os.Args[2], os.Args[3])
	if e != nil {
		fmt.Fprintln(os.Stderr, "Private scanner dispatch refused; do not infer cleanup")
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if out.State != "no_job" && out.State != "completed" && out.State != "completed_partial" && out.State != "completed_stale_db" {
		os.Exit(1)
	}
}
