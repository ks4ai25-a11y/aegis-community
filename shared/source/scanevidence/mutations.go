// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"regexp"
	"time"
)

type MutationBinding struct {
	Owner      string `json:"owner_id"`
	Authorizer string `json:"authorizer_id"`
	Engine     string `json:"engine_digest"`
	Registry   string `json:"registry_digest"`
	Policy     string `json:"policy_digest"`
	Namespace  string `json:"registry_namespace_digest"`
	Broker     string `json:"broker_binding_digest"`
	Created    string `json:"created_at"`
	Digest     string `json:"-"`
}

type AllocationGeneration struct {
	ID       string `json:"generation_id"`
	Job      string `json:"job_id"`
	Binding  string `json:"binding_digest"`
	State    string `json:"state"`
	Deadline int64  `json:"deadline_unix"`
}

type MutationRequest struct {
	Generation string `json:"generation_id"`
	Job        string `json:"job_id"`
	Tool       string `json:"tool_id"`
	Operation  string `json:"operation"`
	Launch     string `json:"launch_digest"`
	Descriptor string `json:"descriptor_digest"`
	EngineID   string `json:"target_engine_id"`
}

type MutationIntent struct {
	ID        string          `json:"intent_id"`
	Request   MutationRequest `json:"request"`
	Workspace string          `json:"workspace_digest"`
	Container string          `json:"container"`
	State     string          `json:"state"`
	Response  string          `json:"response_digest,omitempty"`
	Status    int             `json:"response_status,omitempty"`
	EngineID  string          `json:"result_engine_id,omitempty"`
}

type MutationAdmission struct {
	Intent MutationIntent `json:"intent"`
	Replay bool           `json:"replay"`
}

type MutationCompletion struct {
	Intent     string `json:"intent_id"`
	Generation string `json:"generation_id"`
	Status     int    `json:"response_status"`
	EngineID   string `json:"engine_id"`
	Response   string `json:"response_digest"`
}

var mutationTools = map[string]bool{"bandit": true, "semgrep_ce": true, "gitleaks": true, "syft": true, "trivy": true, "osv_v2": true}

var allocationID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MutationBindingRecord carries selection metadata, never a daemon grant.
// Document.Digest stays excluded from JSON to preserve migration016 identity.
type MutationBindingRecord struct {
	Digest   string          `json:"binding_digest"`
	Document MutationBinding `json:"document"`
}

func (b MutationBindingRecord) Valid(owner, id, engine, registry, policy, namespace string) bool {
	d := b.Document
	_, e := time.Parse(time.RFC3339Nano, d.Created)
	return b.Digest == digest(d) && d.Digest == "" && owner != "" && len(owner) <= 128 && d.Owner == owner && cleanupIdentity.MatchString(id) && d.Authorizer == id && hash.MatchString(engine) && d.Engine == engine && hash.MatchString(registry) && d.Registry == registry && hash.MatchString(policy) && d.Policy == policy && hash.MatchString(namespace) && d.Namespace == namespace && hash.MatchString(d.Broker) && e == nil
}
func (r MutationRequest) Valid() bool {
	return allocationID.MatchString(r.Generation) && cleanupJob.MatchString(r.Job) && mutationTools[r.Tool] && hash.MatchString(r.Launch) && hash.MatchString(r.Descriptor) && ((r.Operation == "create" && r.EngineID == "") || ((r.Operation == "start" || r.Operation == "remove") && allocationID.MatchString(r.EngineID)))
}
func (m MutationIntent) Valid() bool {
	r := m.Request
	expected := digest(struct {
		Domain               string
		Request              MutationRequest
		Workspace, Container string
	}{"aegis-scanner-mutation-intent-v1", r, m.Workspace, m.Container})
	if !r.Valid() || m.ID != expected || !hash.MatchString(m.Workspace) || !container.MatchString(m.Container) {
		return false
	}
	if m.State == "pending" {
		return m.Response == "" && m.Status == 0 && m.EngineID == ""
	}
	// A repaired intent never carries a native status: Response is the digest
	// of its retained repair record. A create may be repaired as not created.
	if m.State == "repaired" {
		return hash.MatchString(m.Response) && m.Status == 0 && ((r.Operation == "create" && (m.EngineID == "" || allocationID.MatchString(m.EngineID))) || (r.Operation != "create" && m.EngineID == r.EngineID))
	}
	return m.State == "completed" && hash.MatchString(m.Response) && allocationID.MatchString(m.EngineID) && ((r.Operation == "create" && m.Status == 201) || (r.Operation != "create" && m.Status == 204 && m.EngineID == r.EngineID))
}

// Settled reports a native completion or an explicit repair. Neither is
// independent absence; release still requires exact observation.
func (m MutationIntent) Settled() bool { return m.State == "completed" || m.State == "repaired" }

func (c MutationCompletion) Valid() bool {
	return hash.MatchString(c.Intent) && allocationID.MatchString(c.Generation) && allocationID.MatchString(c.EngineID) && hash.MatchString(c.Response) && (c.Status == 201 || c.Status == 204)
}

type AuthorizerLaunchRequest struct {
	Container string `json:"container_name"`
	Challenge string `json:"challenge"`
	Operation string `json:"operation"`
}

func (r AuthorizerLaunchRequest) Valid() bool {
	return container.MatchString(r.Container) && liveChallenge.MatchString(r.Challenge) && (r.Operation == "create" || r.Operation == "start" || r.Operation == "remove")
}

// AuthorizerLaunch is a challenge-bound read of the selected dispatch. Only a
// separately committed MutationIntent is admission. It contains no lease token.
type AuthorizerLaunch struct {
	Schema            string                `json:"schema_version"`
	Challenge         string                `json:"challenge"`
	Operation         string                `json:"operation"`
	Binding           MutationBindingRecord `json:"binding"`
	Generation        AllocationGeneration  `json:"generation"`
	Launch            LaunchRecord          `json:"launch"`
	Workspace         WorkspaceRecord       `json:"workspace"`
	Guards            GuardSet              `json:"guard_set"`
	LeaseUntil        int64                 `json:"lease_until_unix"`
	Observed          string                `json:"observed_at"`
	MetadataOnly      bool                  `json:"controller_metadata_only"`
	EngineAuthorized  bool                  `json:"engine_write_authorized"`
	CleanupAuthorized bool                  `json:"cleanup_release_authorized"`
}

func (d AuthorizerLaunch) Valid(v AuthorizerIdentity, namespace, lock string, r AuthorizerLaunchRequest, now time.Time) bool {
	if ValidateAuthorizerIdentity(v, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, now) != nil {
		return false
	}
	b, g, l, w := d.Binding, d.Generation, d.Launch.Document, d.Workspace.Document
	observed, oe := time.Parse(time.RFC3339Nano, d.Observed)
	deadline, de := time.Parse(time.RFC3339, l.Deadline)
	created, ce := time.Parse(time.RFC3339Nano, l.Created)
	wc, we := time.Parse(time.RFC3339Nano, w.Created)
	bc, be := time.Parse(time.RFC3339Nano, b.Document.Created)
	if !r.Valid() || d.Schema != "1.0" || d.Challenge != r.Challenge || d.Operation != r.Operation || !d.MetadataOnly || d.EngineAuthorized || d.CleanupAuthorized || !b.Valid(v.Owner, v.ID, v.Engine, v.Registry, v.Policy, namespace) || !allocationID.MatchString(g.ID) || !cleanupJob.MatchString(g.Job) || g.Binding != b.Digest || (g.State != "open" && g.State != "closed") || !d.Guards.Valid() || oe != nil || observed.After(now.Add(2*time.Second)) || de != nil || ce != nil || we != nil || be != nil || bc.After(observed) || wc.After(created) || created.After(observed) || !deadline.After(created) || g.Deadline != deadline.Unix() || d.LeaseUntil > g.Deadline {
		return false
	}
	if r.Operation != "remove" && (g.State != "open" || d.LeaseUntil <= observed.Unix() || g.Deadline <= observed.Unix()) {
		return false
	}
	if l.Schema != "1.2" || !GuardedLaunchRevision(l) || d.Launch.Digest != digest(l) || d.Workspace.Digest != digest(w) || l.Owner != v.Owner || w.Owner != v.Owner || l.Job != g.Job || w.Job != g.Job || l.Plan.Container != r.Container || l.Plan.Engine != v.Engine || l.Plan.Registry != v.Registry || l.Plan.Registry != w.Plan.Registry || l.Plan.Tool != w.Plan.Tool || l.Plan.Workspace != w.Plan.Workspace || !cleanupWorkspace.MatchString(l.Plan.Workspace) || l.Plan.Snapshot != w.Plan.Snapshot || !hash.MatchString(l.Plan.Snapshot) || !mutationTools[l.Plan.Tool] || l.GuardSet != d.Guards.Digest || d.Guards.Architecture(l.Plan.Guard) != l.Plan.Architecture || l.GuardProtocol != GuardProtocol || w.Schema != "1.0" || l.Request != w.Request || !hash.MatchString(l.Request) || l.App != w.App || l.App != "app_demo" || l.Repository != w.Repository || l.Repository == "" || len(l.Repository) > 128 || l.Map != w.Map || !hash.MatchString(l.Map) || l.Lock != lock || w.Lock != lock || !hash.MatchString(lock) || l.Deadline != w.Deadline || !hash.MatchString(l.Image) || l.Version == "" || len(l.Version) > 64 || l.Profile != "repo_offline-network-none-v1" || l.Duration < 1 || l.Duration > 120 {
		return false
	}
	return true
}

func NewMutationIntent(r MutationRequest, workspace, name string) (MutationIntent, error) {
	m := MutationIntent{Request: r, Workspace: workspace, Container: name, State: "pending"}
	m.ID = digest(struct {
		Domain               string
		Request              MutationRequest
		Workspace, Container string
	}{"aegis-scanner-mutation-intent-v1", r, workspace, name})
	if !m.Valid() {
		return MutationIntent{}, ErrReceipt
	}
	return m, nil
}
