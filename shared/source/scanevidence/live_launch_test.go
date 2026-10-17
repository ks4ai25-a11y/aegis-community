// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func liveSample(t *testing.T) LiveLaunchRecord {
	t.Helper()
	b, e := os.ReadFile("../../../contracts/samples/ScannerLiveLaunchRecordV1.json")
	if e != nil {
		t.Fatal(e)
	}
	var r LiveLaunchRecord
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("sample decode")
	}
	return r
}
func TestLiveLaunchSyntheticSampleAndRefusals(t *testing.T) {
	for _, kind := range []string{"valid", "challenge", "name", "digest", "engine-authority", "cleanup-authority", "not-live", "cancel", "held", "terminal", "expired-lease", "expired-deadline", "wrong-worker", "wrong-engine", "journal", "legacy", "future-binding"} {
		t.Run(kind, func(t *testing.T) {
			r := liveSample(t)
			d := &r.Document
			switch kind {
			case "challenge":
				d.Challenge = strings.Repeat("d", 32)
			case "name":
				d.Container = "aegis-scan-" + strings.Repeat("e", 32)
			case "engine-authority":
				d.EngineAuthorized = true
			case "cleanup-authority":
				d.CleanupAuthorized = true
			case "not-live":
				d.Live = false
			case "cancel":
				d.Context.Document.CancelRequested = true
			case "held":
				d.Context.Document.DispatchState = "cleanup_required"
			case "terminal":
				d.Context.Document.JobState = "completed"
			case "expired-lease":
				d.Context.Document.LeaseUntil = d.Context.Document.Observed
			case "expired-deadline":
				d.Context.Document.Deadline = d.Context.Document.Observed
			case "wrong-worker":
				d.Context.Document.Worker = "wrong-worker"
			case "wrong-engine":
				d.EngineBinding.Document.Engine = digest("wrong")
			case "journal":
				d.JournalBinding.Document.Namespace = digest("wrong")
			case "legacy":
				d.Context.Document.Launches[0].Document.Schema = "1.1"
				d.Context.Document.Launches[0].Document.Plan.JournalBinding = ""
				d.Context.Document.Launches[0].Document.Plan.JournalNamespace = ""
			case "future-binding":
				d.BrokerBinding.Document.Created = "2026-10-16T00:00:02Z"
			}
			// Reseal all nested documents so refusal tests check semantic invariants,
			// rather than succeeding only because a stale digest happened to mismatch.
			for i := range d.Context.Document.Launches {
				d.Context.Document.Launches[i].Digest = digest(d.Context.Document.Launches[i].Document)
			}
			d.Context.Digest = digest(d.Context.Document)
			d.EngineBinding.Digest = digest(d.EngineBinding.Document)
			d.JournalBinding.Digest = digest(d.JournalBinding.Document)
			d.BrokerBinding.Digest = digest(d.BrokerBinding.Document)
			r.Digest = digest(*d)
			if kind == "digest" {
				r.Digest = digest("wrong")
			}
			c := d.Context.Document
			e := ValidateLiveLaunch(r, "example-owner", "example-observer", "aegis-scan-"+strings.Repeat("a", 32), strings.Repeat("c", 32), "sha256:"+strings.Repeat("0", 64), "sha256:"+strings.Repeat("1", 64), c.Lock)
			if (e == nil) != (kind == "valid") {
				t.Fatal("live observation validation disagrees with invariant", e)
			}
		})
	}
}
