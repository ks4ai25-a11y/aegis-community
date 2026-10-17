// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"testing"
)

func TestGuardedLaunchRevisionCannotSilentlyDiscardJournalScope(t *testing.T) {
	for _, row := range []struct {
		schema, binding, namespace string
		valid                      bool
	}{
		{"1.1", "", "", true}, {"1.2", source.Hash([]byte("binding")), source.Hash([]byte("namespace")), true},
		{"1.1", source.Hash([]byte("binding")), "", false}, {"1.2", "", "", false}, {"1.2", source.Hash([]byte("binding")), "", false}, {"1.2", "bad", source.Hash([]byte("namespace")), false}, {"1.0", "", "", false},
	} {
		l := Launch{Schema: row.schema, Plan: LaunchPlan{JournalBinding: row.binding, JournalNamespace: row.namespace}}
		if GuardedLaunchRevision(l) != row.valid {
			t.Fatal(row)
		}
	}
}
