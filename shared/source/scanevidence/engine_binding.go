// SPDX-License-Identifier: Apache-2.0
package scanevidence

import "time"

// EngineBinding is local operator provisioning, not host attestation or a
// cleanup capability. Its scope is immutable for this controller database.
type EngineBinding struct {
	Schema   string `json:"schema_version"`
	Owner    string `json:"owner_id"`
	Engine   string `json:"engine_digest"`
	Registry string `json:"registry_digest"`
	Created  string `json:"created_at"`
}
type EngineBindingRecord struct {
	Digest   string        `json:"binding_digest"`
	Document EngineBinding `json:"document"`
}

func (r EngineBindingRecord) Valid(owner string) bool {
	d := r.Document
	t, e := time.Parse(time.RFC3339Nano, d.Created)
	return d.Schema == "1.0" && owner != "" && len(owner) <= 128 && d.Owner == owner && hash.MatchString(d.Engine) && hash.MatchString(d.Registry) && e == nil && t.Location() == time.UTC && t.Format(time.RFC3339Nano) == d.Created && r.Digest == digest(d)
}
