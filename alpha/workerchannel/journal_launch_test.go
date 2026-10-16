//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestJournalLaunchClientRequiresExactScopeAndGuardedRevision(t *testing.T) {
	for _, kind := range []string{"valid", "downgrade", "namespace", "binding", "missing"} {
		t.Run(kind, func(t *testing.T) {
			lease := claim()
			record, plan := clientLaunchFixture(lease)
			plan.JournalBinding = source.Hash([]byte("binding"))
			plan.JournalNamespace = source.Hash([]byte("namespace"))
			record.Document.Plan = plan
			record.Document.Schema = "1.2"
			switch kind {
			case "downgrade":
				record.Document.Schema = "1.1"
			case "namespace":
				record.Document.Plan.JournalNamespace = source.Hash([]byte("other"))
			case "binding":
				record.Document.Plan.JournalBinding = source.Hash([]byte("other"))
			case "missing":
				record.Document.Plan.JournalBinding = ""
			}
			raw, _ := json.Marshal(record.Document)
			record.Digest = source.Hash(raw)
			c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"state": "authorized", "record": record})
			}))
			got, e := c.RegisterLaunch(context.Background(), lease, plan, record.Document.Version, record.Document.Image)
			if kind == "valid" {
				if e != nil || got != record {
					t.Fatal(got, e)
				}
			} else if e == nil {
				t.Fatal("altered journal acknowledgement accepted", kind)
			}
		})
	}
}
func TestVerifierJournalLaunchRevisionRemainsMetadataWithFalseCleanupFlags(t *testing.T) {
	for _, kind := range []string{"valid", "downgrade", "missing", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			_, r := verifierDocuments(t)
			launch := &r.Document.Launches[0].Document
			launch.Schema = "1.2"
			launch.Plan.JournalBinding = source.Hash([]byte("binding"))
			launch.Plan.JournalNamespace = source.Hash([]byte("namespace"))
			switch kind {
			case "downgrade":
				launch.Schema = "1.1"
			case "missing":
				launch.Plan.JournalNamespace = ""
			case "cleanup":
				r.Document.CleanupConfirmed = true
			}
			resealVerifierContext(&r)
			d := r.Document
			e := scanevidence.ValidateCleanupContext(r, d.Owner, d.Verifier, d.Job, d.Engine, d.Registry, d.Lock)
			if kind == "valid" {
				if e != nil || d.CleanupConfirmed || d.LateStartExcluded || d.LeasesExcluded {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("mixed scope revision/cleanup accepted", kind)
			}
		})
	}
}
