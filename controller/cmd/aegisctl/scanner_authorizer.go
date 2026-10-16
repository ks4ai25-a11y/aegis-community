// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scantransport"
	"aegis.local/controller/internal/store"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func runScannerAuthorizer(root string, args []string) {
	const usage = "usage: scanner-authorizer enroll ID MINUTES ENGINE_DIGEST REGISTRY_DIGEST POLICY_DIGEST PRIVATE_FILE | scanner-authorizer revoke ID | scanner-authorizer probe PRIVATE_FILE"
	if len(args) == 3 && args[1] == "probe" {
		socket := os.Getenv("AEGIS_SCANNER_SOCKET")
		if socket == "" {
			die("Private scanner socket is not configured")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		v, e := scantransport.ProbeAuthorizer(ctx, socket, args[2])
		if e != nil {
			die("Authorizer probe refused")
		}
		fmt.Printf("Authorizer %s authenticated for owner %s until %s; enrollment only; mutation admission unavailable\n", v.ID, v.Owner, v.Expires)
		return
	}
	if !(len(args) == 3 && args[1] == "revoke" || len(args) == 8 && args[1] == "enroll") {
		die(usage)
	}
	s, e := store.Open(filepath.Join(root, "aegis.db"))
	if e != nil {
		die("Authorizer state unavailable")
	}
	defer s.DB.Close()
	owner, e := s.Get("repository_mount_owner")
	if e != nil {
		die("Connect an owned provisioned repository before authorizer enrollment")
	}
	r := &scannerauth.Registry{S: s}
	if args[1] == "revoke" {
		if e = r.RevokeAuthorizer(owner, args[2]); e != nil {
			die("Authorizer revocation refused")
		}
		fmt.Println("Authorizer revoked; cleanup admission remains held")
		return
	}
	minutes, e := strconv.Atoi(args[3])
	if e != nil {
		die("Authorizer lifetime must be 1–1440 minutes")
	}
	v, e := r.EnrollAuthorizerFile(owner, args[2], minutes, args[4], args[5], args[6], args[7])
	if e != nil {
		die("Authorizer enrollment refused")
	}
	fmt.Printf("Authorizer %s enrolled for owner %s until %s; credential written privately; mutation admission unavailable\n", v.ID, v.Owner, v.Expires)
}
