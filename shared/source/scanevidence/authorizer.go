// SPDX-License-Identifier: Apache-2.0
package scanevidence

import "time"

const ScannerAuthorizerRole = "scanner-engine-authorizer"

// AuthorizerIdentity describes enrollment, not an engine mutation grant. Its
// policy/engine/registry cannot be replaced by request fields or a worker role.
type AuthorizerIdentity struct {
	Schema   string `json:"schema_version"`
	Role     string `json:"role"`
	ID       string `json:"authorizer_id"`
	Owner    string `json:"owner_id"`
	Engine   string `json:"engine_digest"`
	Registry string `json:"registry_digest"`
	Policy   string `json:"policy_digest"`
	State    string `json:"state"`
	Expires  string `json:"expires_at"`
	Created  string `json:"created_at"`
}

func ValidateAuthorizerIdentity(v AuthorizerIdentity, owner, id, engine, registry, policy string, now time.Time) error {
	created, ce := time.Parse(time.RFC3339Nano, v.Created)
	expires, ee := time.Parse(time.RFC3339, v.Expires)
	if v.Schema != "1.0" || v.Role != ScannerAuthorizerRole || !cleanupIdentity.MatchString(id) || v.ID != id || owner == "" || len(owner) > 128 || v.Owner != owner || !hash.MatchString(engine) || v.Engine != engine || !hash.MatchString(registry) || v.Registry != registry || !hash.MatchString(policy) || v.Policy != policy || v.State != "active" || ce != nil || ee != nil || created.After(now.Add(2*time.Second)) || !expires.After(now) || !expires.After(created) || expires.After(created.Add(24*time.Hour)) {
		return ErrCleanupContext
	}
	return nil
}
