// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"sort"
	"time"
)

// Sealed crash repair (ADR 057). A create, start or remove can stay pending
// when the authorizer, daemon or acknowledgement is lost mid-write. Repair
// resolves each pending intent only from positive evidence, observed on the
// original engine under a fence that excludes a late daemon Allow:
//
//   - the native plugin journal is sealed in quarantine, which only a process
//     holding the journal's exclusive lock can write, so the authorizer that
//     admitted the intent is no longer serving that namespace; and
//   - a daemon process started after that seal has activated the quarantine
//     plugin, so no daemon process that received an earlier Allow survives.
//
// A repair is recorded once per intent, retained and immutable. It never
// fabricates a native response status and never proves absence by itself.

const (
	RepairCreated    = "created"
	RepairNotCreated = "not_created"
	RepairStarted    = "started"
	RepairNotStarted = "not_started"
	RepairRemoved    = "removed"
)

// RepairFence identifies the sealed journal evidence the reconciler checked.
// Policy must equal AdmittedJournalSeal of the generation's binding.
type RepairFence struct {
	Policy     string `json:"journal_policy_digest"`
	Quarantine string `json:"quarantine_digest"`
	Activation string `json:"activation_digest"`
}

// MutationResolution resolves one pending intent. EngineID is the observed
// exact container ID for "created", empty for "not_created", and the intent's
// own target for start/remove outcomes. Evidence digests the journal records
// and engine observation used, so the record names what was relied on.
type MutationResolution struct {
	Intent    string `json:"intent_id"`
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
	EngineID  string `json:"engine_id"`
	Evidence  string `json:"evidence_digest"`
}

type MutationRepairRequest struct {
	Job         string               `json:"job_id"`
	Generation  string               `json:"generation_id"`
	Membership  string               `json:"membership_digest"`
	Engine      string               `json:"engine_digest"`
	Namespace   string               `json:"registry_namespace_digest"`
	Fence       RepairFence          `json:"fence"`
	Resolutions []MutationResolution `json:"resolutions"`
}

// MutationRepair is the retained record for one repaired intent.
type MutationRepair struct {
	Schema     string             `json:"schema_version"`
	Reconciler string             `json:"reconciler_id"`
	Job        string             `json:"job_id"`
	Generation string             `json:"generation_id"`
	Membership string             `json:"membership_digest"`
	Engine     string             `json:"engine_digest"`
	Namespace  string             `json:"registry_namespace_digest"`
	Fence      RepairFence        `json:"fence"`
	Resolution MutationResolution `json:"resolution"`
	Repaired   string             `json:"repaired_at"`
	Digest     string             `json:"repair_digest"`
}

type MutationRepairResult struct {
	Schema           string           `json:"schema_version"`
	Repairs          []MutationRepair `json:"repairs"`
	CleanupReleased  bool             `json:"cleanup_release_authorized"`
	EngineWritesDone bool             `json:"engine_writes_authorized"`
}

// AdmittedJournalSeal is the local journal policy written by an admitted
// plugin: its provisioning policy digest bound to the selected binding.
func AdmittedJournalSeal(policy, binding string) string {
	return digest(struct{ Domain, Policy, Binding string }{"aegis-controller-admitted-journal-v1", policy, binding})
}

func (f RepairFence) Valid() bool {
	return hash.MatchString(f.Policy) && hash.MatchString(f.Quarantine) && hash.MatchString(f.Activation)
}

// ValidFor checks one resolution against the pending intent it resolves.
func (x MutationResolution) ValidFor(m MutationIntent) bool {
	if x.Intent != m.ID || m.State != "pending" || x.Operation != m.Request.Operation || !hash.MatchString(x.Evidence) {
		return false
	}
	switch x.Outcome {
	case RepairCreated:
		return x.Operation == "create" && allocationID.MatchString(x.EngineID)
	case RepairNotCreated:
		return x.Operation == "create" && x.EngineID == ""
	case RepairStarted, RepairNotStarted:
		return x.Operation == "start" && x.EngineID == m.Request.EngineID
	case RepairRemoved:
		return x.Operation == "remove" && x.EngineID == m.Request.EngineID
	}
	return false
}

func (r MutationRepairRequest) Valid() bool {
	if !cleanupJob.MatchString(r.Job) || !allocationID.MatchString(r.Generation) || !hash.MatchString(r.Membership) || !hash.MatchString(r.Engine) || !hash.MatchString(r.Namespace) || !r.Fence.Valid() || len(r.Resolutions) < 1 || len(r.Resolutions) > 18 {
		return false
	}
	outcomes := map[string]string{RepairCreated: "create", RepairNotCreated: "create", RepairStarted: "start", RepairNotStarted: "start", RepairRemoved: "remove"}
	for i, x := range r.Resolutions {
		if !hash.MatchString(x.Intent) || (i > 0 && r.Resolutions[i-1].Intent >= x.Intent) || outcomes[x.Outcome] != x.Operation || !hash.MatchString(x.Evidence) || (x.EngineID == "") != (x.Outcome == RepairNotCreated) || (x.EngineID != "" && !allocationID.MatchString(x.EngineID)) {
			return false
		}
	}
	return true
}

// PendingIntents lists the unresolved obligations of a membership, sorted by
// intent ID, which is the order a repair request must resolve them in.
func PendingIntents(m ReconciliationMembership) []MutationIntent {
	out := []MutationIntent{}
	for _, x := range m.Mutations {
		if x.State == "pending" {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func NewMutationRepair(reconciler string, r MutationRepairRequest, x MutationResolution, now time.Time) MutationRepair {
	m := MutationRepair{Schema: "1.0", Reconciler: reconciler, Job: r.Job, Generation: r.Generation, Membership: r.Membership, Engine: r.Engine, Namespace: r.Namespace, Fence: r.Fence, Resolution: x, Repaired: now.UTC().Format(time.RFC3339Nano)}
	m.Digest = repairDigest(m)
	return m
}

func repairDigest(m MutationRepair) string {
	m.Digest = ""
	return digest(struct {
		Domain string
		Value  MutationRepair
	}{"aegis-scanner-mutation-repair-v1", m})
}

// Valid checks a retained repair record's own integrity.
func (m MutationRepair) Valid() bool {
	_, e := time.Parse(time.RFC3339Nano, m.Repaired)
	return m.Schema == "1.0" && cleanupIdentity.MatchString(m.Reconciler) && cleanupJob.MatchString(m.Job) && allocationID.MatchString(m.Generation) && hash.MatchString(m.Membership) && hash.MatchString(m.Engine) && hash.MatchString(m.Namespace) && m.Fence.Valid() && hash.MatchString(m.Resolution.Intent) && hash.MatchString(m.Resolution.Evidence) && e == nil && m.Digest == repairDigest(m)
}

// RepairedIntent is the intent state a valid repair produces.
func RepairedIntent(m MutationIntent, r MutationRepair) MutationIntent {
	m.State, m.Response, m.Status, m.EngineID = "repaired", r.Digest, 0, r.Resolution.EngineID
	return m
}

func DecodeMutationRepair(b []byte) (MutationRepair, error) {
	var m MutationRepair
	if len(b) > 8192 || json.Unmarshal(b, &m) != nil || !m.Valid() {
		return MutationRepair{}, ErrNotReleasable
	}
	canonical, _ := json.Marshal(m)
	if string(canonical) != string(b) {
		return MutationRepair{}, ErrNotReleasable
	}
	return m, nil
}

// AuthorizerIntentRequest asks for one retained intent of the authorizer's
// own original binding. AuthorizerIntentRead answers it; it grants nothing.
type AuthorizerIntentRequest struct {
	Generation string `json:"generation_id"`
	Intent     string `json:"intent_id"`
}

type AuthorizerIntentRead struct {
	Schema string          `json:"schema_version"`
	Found  bool            `json:"found"`
	Intent *MutationIntent `json:"intent"`
	Repair *MutationRepair `json:"repair"`
}

func (r AuthorizerIntentRequest) Valid() bool {
	return allocationID.MatchString(r.Generation) && hash.MatchString(r.Intent)
}

// Valid checks the read answers exactly the request: absent means no intent
// was ever admitted under that closed generation; a repair matches its intent.
func (a AuthorizerIntentRead) Valid(r AuthorizerIntentRequest) bool {
	if a.Schema != "1.0" || !r.Valid() {
		return false
	}
	if !a.Found {
		return a.Intent == nil && a.Repair == nil
	}
	if a.Intent == nil || !a.Intent.Valid() || a.Intent.ID != r.Intent || a.Intent.Request.Generation != r.Generation {
		return false
	}
	if a.Intent.State != "repaired" {
		return a.Repair == nil
	}
	x := a.Repair
	return x != nil && x.Valid() && x.Digest == a.Intent.Response && x.Resolution.Intent == r.Intent && x.Resolution.EngineID == a.Intent.EngineID && x.Resolution.Operation == a.Intent.Request.Operation && x.Generation == r.Generation && x.Job == a.Intent.Request.Job
}
