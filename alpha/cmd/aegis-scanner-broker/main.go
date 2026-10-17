// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/alpha/scanbroker"
	"aegis.local/alpha/worker"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) != 10 {
		fmt.Fprintln(os.Stderr, "usage: aegis-scanner-broker BROKER_SOCKET DISPATCH_CREDENTIAL CONTROLLER_SOCKET WORKER_CREDENTIAL OWNER WORKER_ID SOURCE_ROOT ASSET_ROOT JOURNAL_ROOT")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := scanbroker.Server{Credential: os.Args[2], Worker: worker.Config{RequireEngineBinding: true, ExpectedBrokerID: os.Args[6], Socket: os.Args[3], Credential: os.Args[4], Owner: os.Args[5], SourceRoot: os.Args[7], AssetRoot: os.Args[8], EngineJournalRoot: os.Args[9]}}
	if e := server.Serve(ctx, os.Args[1]); e != nil {
		fmt.Fprintln(os.Stderr, "Private scanner broker stopped; cleanup admission unchanged")
		os.Exit(1)
	}
}
