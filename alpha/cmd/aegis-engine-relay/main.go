// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/alpha/enginerelay"
	"aegis.local/source/privateipc"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) != 3 || enginerelay.Endpoint(os.Args[2]) != nil {
		fmt.Fprintln(os.Stderr, "usage: aegis-engine-relay PRIVATE_UNIX_SOCKET FIXED_LOOPBACK_HOST_PORT")
		os.Exit(1)
	}
	listener, e := privateipc.Listen(os.Args[1])
	if e != nil {
		fmt.Fprintln(os.Stderr, "private engine relay unavailable")
		os.Exit(1)
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if enginerelay.Serve(ctx, listener, os.Args[2]) != nil {
		fmt.Fprintln(os.Stderr, "private engine relay stopped unconfirmed")
		os.Exit(1)
	}
}
