// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/controller/internal/recovery"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const recoveryUsage = "backup bundle NEW_ABSOLUTE_DIRECTORY [--json] | backup verify BUNDLE_DIRECTORY [--json] | backup restore BUNDLE_DIRECTORY NEW_ABSOLUTE_DIRECTORY --confirm BUNDLE_DIGEST [--json]"

func handleRecovery(args []string, data string) bool {
	if len(args) == 0 || (args[0] != "bundle" && args[0] != "verify" && args[0] != "restore") {
		return false
	}
	jsonOutput := len(args) > 0 && args[len(args)-1] == "--json"
	if jsonOutput {
		args = args[:len(args)-1]
	}
	if len(args) == 2 && args[1] == "--help" {
		fmt.Println(recoveryUsage + "\nThe demo-http-v1 bundle binds private database, persisted gateway policy and scanner-lock bytes. Restore requires a new destination and exact digest confirmation, invalidates access authority and preserves scanner cleanup holds. It never starts services or overwrites live state.")
		return true
	}
	action := args[0]
	if action == "restore" {
		if len(args) != 5 || args[3] != "--confirm" {
			die("usage: " + recoveryUsage)
		}
	} else if len(args) != 2 {
		die("usage: " + recoveryUsage)
	}
	lock := os.Getenv("AEGIS_SCANNER_LOCK")
	if lock == "" {
		lock = "/opt/aegis/scanners.lock.json"
	}
	config := recovery.Config{Database: filepath.Join(data, "aegis.db"), Gateway: filepath.Join(configRoot(data), "active.Caddyfile"), ToolLock: lock}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var receipt recovery.Receipt
	var e error
	switch action {
	case "bundle":
		receipt, e = recovery.Create(ctx, config, args[1])
	case "verify":
		receipt, e = recovery.Verify(ctx, config, args[1])
	case "restore":
		receipt, e = recovery.Restore(ctx, config, args[1], args[2], args[4])
	}
	if e != nil {
		die("Recovery operation refused or incomplete; verify the trusted tool lock, matching persisted policy, private files, new destination and exact confirmation")
	}
	if jsonOutput {
		json.NewEncoder(os.Stdout).Encode(receipt)
	} else {
		fmt.Printf("Recovery operation %s: %s; live activation and application restore verification remain false\n", receipt.Status, receipt.Bundle)
	}
	return true
}
