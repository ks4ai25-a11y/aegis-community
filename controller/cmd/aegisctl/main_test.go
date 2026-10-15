// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestBackupArgumentsRequireOneExplicitAbsoluteDestination(t *testing.T) {
	for _, args := range [][]string{{"/private-snapshot.db"}, {"create", "/private-snapshot.db"}, {"/private-snapshot.db", "--json"}, {"create", "/private-snapshot.db", "--json"}} {
		path, jsonOutput, e := backupArguments(args)
		if e != nil || path != "/private-snapshot.db" || jsonOutput != (args[len(args)-1] == "--json") {
			t.Fatal(args, path, jsonOutput, e)
		}
	}
	for _, args := range [][]string{{}, {"create"}, {"relative.db"}, {"/private/../snapshot.db"}, {"--json", "/snapshot.db"}, {"create", "/snapshot.db", "--unknown"}, {"create", "/snapshot.db", "extra"}, {"create", "/snapshot.db", "--json", "--json"}} {
		if _, _, e := backupArguments(args); e == nil {
			t.Fatal("ambiguous backup accepted", args)
		}
	}
}
