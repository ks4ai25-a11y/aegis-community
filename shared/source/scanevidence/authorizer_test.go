// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"testing"
	"time"
)

func TestAuthorizerIdentityBindsAllScopeAndLifetime(t *testing.T) {
	now := time.Now().UTC()
	v := AuthorizerIdentity{Schema: "1.0", Role: ScannerAuthorizerRole, ID: "gate-a", Owner: "owner-a", Engine: source.Hash([]byte("engine")), Registry: source.Hash([]byte("registry")), Policy: source.Hash([]byte("policy")), State: "active", Created: now.Format(time.RFC3339Nano), Expires: now.Add(time.Minute).Format(time.RFC3339)}
	check := func(x AuthorizerIdentity) error {
		return ValidateAuthorizerIdentity(x, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, now)
	}
	if check(v) != nil {
		t.Fatal("valid identity refused")
	}
	for _, kind := range []string{"role", "owner", "id", "engine", "registry", "policy", "state", "expired", "future", "lifetime", "schema"} {
		t.Run(kind, func(t *testing.T) {
			x := v
			switch kind {
			case "role":
				x.Role = CleanupObserverRole
			case "owner":
				x.Owner = "owner-b"
			case "id":
				x.ID = "gate-b"
			case "engine":
				x.Engine = source.Hash([]byte("other"))
			case "registry":
				x.Registry = source.Hash([]byte("other"))
			case "policy":
				x.Policy = source.Hash([]byte("other"))
			case "state":
				x.State = "revoked"
			case "expired":
				x.Expires = now.Format(time.RFC3339)
			case "future":
				x.Created = now.Add(time.Hour).Format(time.RFC3339Nano)
			case "lifetime":
				x.Expires = now.Add(25 * time.Hour).Format(time.RFC3339)
			case "schema":
				x.Schema = "1.1"
			}
			if check(x) == nil {
				t.Fatal("altered authorizer accepted")
			}
		})
	}
}
