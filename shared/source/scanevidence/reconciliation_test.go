// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func fixedReconciliation(t *testing.T) (ReconciliationSnapshot, ReconcilerIdentity, ReconciliationRequest, time.Time) {
	t.Helper()
	read := func(name string, out any) {
		t.Helper()
		b, err := os.ReadFile("../../../contracts/samples/" + name + ".json")
		if err != nil || json.Unmarshal(b, out) != nil {
			t.Fatal("fixed synthetic reconciliation sample unavailable")
		}
	}
	var s ReconciliationSnapshot
	var v ReconcilerIdentity
	var r ReconciliationRequest
	read("ScannerReconciliationSnapshotV1", &s)
	read("ScannerReconcilerIdentityV1", &v)
	read("ScannerReconciliationRequestV1", &r)
	now, err := time.Parse(time.RFC3339Nano, s.Observed)
	if err != nil {
		t.Fatal(err)
	}
	return s, v, r, now
}

func TestFixedReconciliationSamplesAreMetadataWithoutReleaseAuthority(t *testing.T) {
	s, v, r, now := fixedReconciliation(t)
	if !v.Valid(now) || !r.Valid() || !ValidateReconciliationSnapshot(s, v, r, now) || s.CleanupReleased || s.EngineWrites || !s.CleanupRequired {
		t.Fatal("invalid fixed metadata samples")
	}
	input := s.Membership
	copy, err := NewReconciliationSnapshot(input, v, r, now)
	if err != nil {
		t.Fatal(err)
	}
	input.Tools[0] = "syft"
	if copy.Membership.Tools[0] != "bandit" {
		t.Fatal("membership retained caller mutable slice")
	}
}

func TestReconciliationSnapshotRefusesChangedScopeFreshnessOrAuthority(t *testing.T) {
	for _, kind := range []string{"schema", "reconciler", "challenge", "stale", "future", "membership-hash", "binding", "owner", "generation", "open", "released", "tools", "unknown-tool", "nil-records", "metadata", "cleanup-required", "cleanup-release", "engine-write", "capability", "expired"} {
		t.Run(kind, func(t *testing.T) {
			s, v, r, now := fixedReconciliation(t)
			switch kind {
			case "schema":
				s.Schema = "2.0"
			case "reconciler":
				s.Reconciler = "other"
			case "challenge":
				s.Challenge = strings.Repeat("3", 32)
			case "stale":
				s.Observed = now.Add(-31 * time.Second).Format(time.RFC3339Nano)
			case "future":
				s.Observed = now.Add(3 * time.Second).Format(time.RFC3339Nano)
			case "membership-hash":
				s.MembershipHash = digest("other")
			case "binding":
				v.Binding = digest("other")
			case "owner":
				v.Owner = "another-owner"
			case "generation":
				r.Generation = strings.Repeat("f", 64)
			case "open":
				s.Membership.Generation.State = "open"
			case "released":
				s.Membership.Generation.State = "released"
			case "tools":
				s.Membership.Tools = []string{"bandit", "bandit"}
			case "unknown-tool":
				s.Membership.Tools = []string{"arbitrary"}
			case "nil-records":
				s.Membership.Mutations = nil
			case "metadata":
				s.MetadataOnly = false
			case "cleanup-required":
				s.CleanupRequired = false
			case "cleanup-release":
				s.CleanupReleased = true
			case "engine-write":
				s.EngineWrites = true
			case "capability":
				v.Capability = "reset"
			case "expired":
				v.Expires = now.Format(time.RFC3339)
			}
			if ValidateReconciliationSnapshot(s, v, r, now) {
				t.Fatal("changed snapshot was accepted")
			}
		})
	}
}

func TestReconciliationDecoderRejectsAmbiguousOrExtendedWireShape(t *testing.T) {
	s, _, _, _ := fixedReconciliation(t)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{"null", string(b) + "{}", strings.Replace(string(b), `"schema_version":"1.0"`, `"schema_version":"1.0","schema_version":"1.0"`, 1), strings.Replace(string(b), `"metadata_only":true`, `"Metadata_Only":true`, 1), strings.TrimSuffix(string(b), "}") + `,"release":true}`, strings.Replace(string(b), `"cleanup_release_authorized":false`, `"cleanup_release_authorized":null`, 1)} {
		if _, err := DecodeReconciliationSnapshot([]byte(wire)); err == nil {
			t.Fatal("ambiguous or extended wire response accepted")
		}
	}
}
