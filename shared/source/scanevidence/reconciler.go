// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import "time"

const ScannerReconcilerRole = "scanner-engine-reconciler"
const ConfirmFencedCleanup = "confirm-fenced-cleanup-v1"

// ReconcilerIdentity reserves narrowly scoped independent cleanup confirmation.
// Enrollment is not mediation, engine absence, or an accepted confirmation.
type ReconcilerIdentity struct {
	Schema     string `json:"schema_version"`
	Role       string `json:"role"`
	Capability string `json:"capability"`
	ID         string `json:"reconciler_id"`
	Owner      string `json:"owner_id"`
	Binding    string `json:"binding_digest"`
	Engine     string `json:"engine_digest"`
	Registry   string `json:"registry_digest"`
	Policy     string `json:"policy_digest"`
	Namespace  string `json:"registry_namespace_digest"`
	State      string `json:"state"`
	Expires    string `json:"expires_at"`
	Created    string `json:"created_at"`
}

func (v ReconcilerIdentity) Valid(now time.Time) bool {
	created, ce := time.Parse(time.RFC3339Nano, v.Created)
	expires, ee := time.Parse(time.RFC3339, v.Expires)
	return v.Schema == "1.0" && v.Role == ScannerReconcilerRole && v.Capability == ConfirmFencedCleanup && cleanupIdentity.MatchString(v.ID) && v.Owner != "" && len(v.Owner) <= 128 && hash.MatchString(v.Binding) && hash.MatchString(v.Engine) && hash.MatchString(v.Registry) && hash.MatchString(v.Policy) && hash.MatchString(v.Namespace) && v.State == "active" && ce == nil && ee == nil && !created.After(now.Add(2*time.Second)) && expires.After(now) && expires.After(created) && !expires.After(created.Add(24*time.Hour))
}
