// SPDX-License-Identifier: Apache-2.0
// An opt-in experimental plugin for a separately provisioned scanner daemon.
package main

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/enginejournal"
	"aegis.local/source"
	"aegis.local/source/privateipc"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func run() error {
	if len(os.Args) == 4 && os.Args[1] == "init" {
		_, e := enginejournal.InitializeEmpty(os.Args[2], os.Args[3])
		return e
	}
	// Paths and digests are operator configuration, never caller-selected RPC data.
	if len(os.Args) != 9 || os.Args[1] != "serve" {
		return fmt.Errorf("usage: aegis-engine-authz init JOURNAL ENGINE_DIGEST | serve SOCKET JOURNAL ENGINE_DIGEST WORK_ROOT UID GID TOOL_LOCK")
	}
	uid, e := strconv.Atoi(os.Args[6])
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(os.Args[7])
	if e != nil {
		return e
	}
	images, b, e := engineauthz.ReadLock(os.Args[8])
	if e != nil {
		return e
	}

	policy, e := engineauthz.Open(engineauthz.Config{WorkRoot: os.Args[5], JournalRoot: os.Args[3], EngineDigest: os.Args[4], UID: uid, GID: gid, Images: images})
	if e != nil {
		return e
	}
	defer policy.Close()
	listener, e := privateipc.Listen(os.Args[2])
	if e != nil {
		return e
	}
	defer listener.Close()
	// Public source identity only. No certificate, source or credential bytes.
	fmt.Fprintf(os.Stderr, "scanner engine authorization ready; tool_lock_digest=%s; cleanup_release_authorized=false\n", source.Hash(b))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return policy.Serve(ctx, listener)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "scanner engine authorization unavailable")
		os.Exit(1)
	}
}
