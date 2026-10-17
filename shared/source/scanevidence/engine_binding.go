// SPDX-License-Identifier: BUSL-1.1
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

// JournalBinding extends, rather than replaces, the immutable engine scope.
// Root and namespace are digests; no host paths or cleanup capability cross IPC.
type JournalBinding struct {
	Schema        string `json:"schema_version"`
	Owner         string `json:"owner_id"`
	EngineBinding string `json:"engine_binding_digest"`
	Root          string `json:"journal_root_digest"`
	Namespace     string `json:"journal_namespace_digest"`
	Created       string `json:"created_at"`
}
type JournalBindingRecord struct {
	Digest   string         `json:"journal_binding_digest"`
	Document JournalBinding `json:"document"`
}

func (r JournalBindingRecord) Valid(owner string, base EngineBindingRecord) bool {
	d := r.Document
	t, e := time.Parse(time.RFC3339Nano, d.Created)
	baseTime, be := time.Parse(time.RFC3339Nano, base.Document.Created)
	return base.Valid(owner) && d.Schema == "1.0" && d.Owner == owner && d.EngineBinding == base.Digest && hash.MatchString(d.Root) && hash.MatchString(d.Namespace) && e == nil && t.Location() == time.UTC && t.Format(time.RFC3339Nano) == d.Created && be == nil && !t.Before(baseTime) && r.Digest == digest(d)
}

// BrokerBinding selects the only enrolled worker allowed to claim fresh work
// in this configured installation. It is not daemon or cleanup attestation.
type BrokerBinding struct {
	Schema  string `json:"schema_version"`
	Owner   string `json:"owner_id"`
	Worker  string `json:"worker_id"`
	Journal string `json:"journal_binding_digest"`
	Created string `json:"created_at"`
}
type BrokerBindingRecord struct {
	Digest   string        `json:"broker_binding_digest"`
	Document BrokerBinding `json:"document"`
}

func (r BrokerBindingRecord) Valid(owner string, base EngineBindingRecord, journal JournalBindingRecord) bool {
	d := r.Document
	t, e := time.Parse(time.RFC3339Nano, d.Created)
	previous, pe := time.Parse(time.RFC3339Nano, journal.Document.Created)
	return journal.Valid(owner, base) && d.Schema == "1.0" && d.Owner == owner && cleanupIdentity.MatchString(d.Worker) && d.Journal == journal.Digest && e == nil && pe == nil && t.Location() == time.UTC && t.Format(time.RFC3339Nano) == d.Created && !t.Before(previous) && r.Digest == digest(d)
}
