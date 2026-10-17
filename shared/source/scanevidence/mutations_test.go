// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestStaticSyntheticAuthorizerContractMatchesSemanticValidator(t *testing.T) {
	b, e := os.ReadFile("../../../contracts/samples/ScannerAuthorizerLaunchV1.json")
	if e != nil {
		t.Fatal(e)
	}
	var d AuthorizerLaunch
	if json.Unmarshal(b, &d) != nil {
		t.Fatal("invalid synthetic sample")
	}
	scope := d.Binding.Document
	now := time.Date(2026, 10, 17, 0, 0, 3, 0, time.UTC)
	v := AuthorizerIdentity{Schema: "1.0", Role: ScannerAuthorizerRole, ID: scope.Authorizer, Owner: scope.Owner, Engine: scope.Engine, Registry: scope.Registry, Policy: scope.Policy, State: "active", Created: scope.Created, Expires: now.Add(time.Minute).Format(time.RFC3339)}
	r := AuthorizerLaunchRequest{Container: d.Launch.Document.Plan.Container, Challenge: d.Challenge, Operation: d.Operation}
	if !d.Valid(v, scope.Namespace, d.Launch.Document.Lock, r, now) {
		t.Fatal("synthetic contract mismatches runtime semantics")
	}
	b, e = os.ReadFile("../../../contracts/samples/ScannerMutationIntentV1.json")
	if e != nil {
		t.Fatal(e)
	}
	var m MutationIntent
	if json.Unmarshal(b, &m) != nil || !m.Valid() {
		t.Fatal("synthetic obligation mismatches runtime identity")
	}
}
