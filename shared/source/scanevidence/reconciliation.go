// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"encoding/json"
	"reflect"
	"sort"
	"time"
)

type ReconciliationRequest struct {
	Job        string `json:"job_id"`
	Generation string `json:"generation_id"`
	Challenge  string `json:"challenge"`
}

func (r ReconciliationRequest) Valid() bool {
	return cleanupJob.MatchString(r.Job) && allocationID.MatchString(r.Generation) && liveChallenge.MatchString(r.Challenge)
}

// ReconciliationMembership is the entire controller-retained allocation set,
// including reservations without a launch and unresolved native obligations.
// Its stable digest excludes observation time, challenge and enrollment ID.
type ReconciliationMembership struct {
	Owner       string                `json:"owner_id"`
	Job         string                `json:"job_id"`
	Request     string                `json:"request_digest"`
	App         string                `json:"app_id"`
	Repository  string                `json:"repository_id"`
	Map         string                `json:"map_digest"`
	Lock        string                `json:"tool_lock_digest"`
	Duration    int                   `json:"duration_limit_seconds"`
	Created     string                `json:"job_created_at"`
	JobState    string                `json:"job_state"`
	Cancelled   bool                  `json:"cancel_requested"`
	Binding     MutationBindingRecord `json:"binding"`
	Generation  AllocationGeneration  `json:"generation"`
	Worker      string                `json:"worker_id"`
	Dispatch    string                `json:"dispatch_state"`
	LeaseUntil  int64                 `json:"lease_until_unix"`
	Fingerprint string                `json:"dispatch_fingerprint"`
	GuardSet    string                `json:"guard_set_digest"`
	Tools       []string              `json:"tool_ids"`
	Workspaces  []WorkspaceRecord     `json:"workspaces"`
	Launches    []LaunchRecord        `json:"launches"`
	Mutations   []MutationIntent      `json:"mutations"`
}

type ReconciliationSnapshot struct {
	Schema          string                   `json:"schema_version"`
	Reconciler      string                   `json:"reconciler_id"`
	Challenge       string                   `json:"challenge"`
	Observed        string                   `json:"observed_at"`
	MembershipHash  string                   `json:"membership_digest"`
	Membership      ReconciliationMembership `json:"membership"`
	MetadataOnly    bool                     `json:"metadata_only"`
	CleanupRequired bool                     `json:"cleanup_required"`
	CleanupReleased bool                     `json:"cleanup_release_authorized"`
	EngineWrites    bool                     `json:"engine_writes_authorized"`
}

func ReconciliationMembershipDigest(m ReconciliationMembership) string {
	return digest(struct {
		Domain string
		Value  ReconciliationMembership
	}{"aegis-scanner-reconciliation-membership-v1", m})
}

func (m ReconciliationMembership) Valid() bool {
	b, g := m.Binding.Document, m.Generation
	created, ce := time.Parse(time.RFC3339Nano, m.Created)
	if g.Deadline < 1 || g.Deadline > 9999999999 {
		return false
	}
	if m.Owner == "" || len(m.Owner) > 128 || !cleanupJob.MatchString(m.Job) || !hash.MatchString(m.Request) || m.App != "app_demo" || m.Repository == "" || len(m.Repository) > 128 || !hash.MatchString(m.Map) || !hash.MatchString(m.Lock) || m.Duration < 1 || m.Duration > 120 || ce != nil || !m.Binding.Valid(m.Owner, b.Authorizer, b.Engine, b.Registry, b.Policy, b.Namespace) || !allocationID.MatchString(g.ID) || g.Job != m.Job || g.Binding != m.Binding.Digest || g.State != "closed" || !time.Unix(g.Deadline, 0).After(created) || !cleanupIdentity.MatchString(m.Worker) || (m.Dispatch != "active" && m.Dispatch != "cleanup_required") || m.LeaseUntil < 0 || m.LeaseUntil > g.Deadline || !hash.MatchString(m.Fingerprint) || !hash.MatchString(m.GuardSet) || len(m.Tools) < 1 || len(m.Tools) > 6 || !sort.StringsAreSorted(m.Tools) || m.Workspaces == nil || len(m.Workspaces) > 6 || m.Launches == nil || len(m.Launches) > 6 || m.Mutations == nil || len(m.Mutations) > 18 {
		return false
	}
	switch m.JobState {
	case "running", "cancelled", "timeout", "failed", "completed", "completed_partial", "completed_stale_db", "tool_error":
	default:
		return false
	}
	selected := map[string]bool{}
	for _, tool := range m.Tools {
		if !mutationTools[tool] || selected[tool] {
			return false
		}
		selected[tool] = true
	}
	workspaces := map[string]WorkspaceRecord{}
	workspaceIDs := map[string]bool{}
	snapshot := ""
	previous := ""
	for _, w := range m.Workspaces {
		d := w.Document
		wc, we := time.Parse(time.RFC3339Nano, d.Created)
		deadline, de := time.Parse(time.RFC3339, d.Deadline)
		if w.Digest != digest(d) || d.Schema != "1.0" || d.Owner != m.Owner || d.Job != m.Job || d.Request != m.Request || d.App != m.App || d.Repository != m.Repository || d.Map != m.Map || d.Lock != m.Lock || !selected[d.Plan.Tool] || d.Plan.Tool <= previous || d.Plan.Registry != b.Registry || !cleanupWorkspace.MatchString(d.Plan.Workspace) || !hash.MatchString(d.Plan.Snapshot) || we != nil || de != nil || wc.Before(created) || !wc.Before(deadline) || deadline.Unix() != g.Deadline {
			return false
		}
		if workspaceIDs[d.Plan.Workspace] || snapshot != "" && snapshot != d.Plan.Snapshot {
			return false
		}
		workspaceIDs[d.Plan.Workspace], snapshot = true, d.Plan.Snapshot
		workspaces[d.Plan.Tool], previous = w, d.Plan.Tool
	}
	launches := map[string]LaunchRecord{}
	names := map[string]bool{}
	previous = ""
	for _, l := range m.Launches {
		d := l.Document
		w, exists := workspaces[d.Plan.Tool]
		lc, le := time.Parse(time.RFC3339Nano, d.Created)
		wc, _ := time.Parse(time.RFC3339Nano, w.Document.Created)
		deadline, de := time.Parse(time.RFC3339, d.Deadline)
		if !exists || l.Digest != digest(d) || !GuardedLaunchRevision(d) || d.Owner != m.Owner || d.Job != m.Job || d.Request != m.Request || d.App != m.App || d.Repository != m.Repository || d.Map != m.Map || d.Lock != m.Lock || !selected[d.Plan.Tool] || d.Plan.Tool <= previous || d.Plan.Registry != b.Registry || d.Plan.Engine != b.Engine || d.Plan.Workspace != w.Document.Plan.Workspace || d.Plan.Snapshot != w.Document.Plan.Snapshot || d.GuardSet != m.GuardSet || d.GuardProtocol != GuardProtocol || !hash.MatchString(d.Plan.Guard) || (d.Plan.Architecture != "amd64" && d.Plan.Architecture != "arm64") || !container.MatchString(d.Plan.Container) || names[d.Plan.Container] || !hash.MatchString(d.Image) || d.Version == "" || len(d.Version) > 64 || d.Duration < 1 || d.Duration > 120 || le != nil || de != nil || lc.Before(wc) || !lc.Before(deadline) || deadline.Unix() != g.Deadline {
			return false
		}
		if d.Schema != "1.2" || d.Profile != "repo_offline-network-none-v1" || d.Duration != m.Duration {
			return false
		}
		names[d.Plan.Container] = true
		launches[d.Plan.Tool], previous = l, d.Plan.Tool
	}
	mutations := map[string]MutationIntent{}
	nativeIDs := map[string]bool{}
	previous = ""
	for _, intent := range m.Mutations {
		r := intent.Request
		l, exists := launches[r.Tool]
		w := workspaces[r.Tool]
		key := r.Tool + "/" + r.Operation
		if !intent.Valid() || intent.ID <= previous || !exists || r.Job != m.Job || r.Generation != g.ID || r.Launch != l.Digest || intent.Workspace != w.Digest || intent.Container != l.Document.Plan.Container || mutations[key].ID != "" {
			return false
		}
		if r.Operation == "create" && intent.State == "completed" {
			if nativeIDs[intent.EngineID] {
				return false
			}
			nativeIDs[intent.EngineID] = true
		}
		mutations[key], previous = intent, intent.ID
	}
	for _, intent := range m.Mutations {
		r := intent.Request
		if r.Operation == "create" {
			continue
		}
		created := mutations[r.Tool+"/create"]
		if created.State != "completed" || created.EngineID != r.EngineID {
			return false
		}
		if r.Operation == "remove" {
			start := mutations[r.Tool+"/start"]
			if start.ID != "" && start.State != "completed" {
				return false
			}
		}
	}
	return true
}

func NewReconciliationSnapshot(m ReconciliationMembership, v ReconcilerIdentity, r ReconciliationRequest, now time.Time) (ReconciliationSnapshot, error) {
	m.Tools = append([]string{}, m.Tools...)
	m.Workspaces = append([]WorkspaceRecord{}, m.Workspaces...)
	m.Launches = append([]LaunchRecord{}, m.Launches...)
	m.Mutations = append([]MutationIntent{}, m.Mutations...)
	s := ReconciliationSnapshot{Schema: "1.0", Reconciler: v.ID, Challenge: r.Challenge, Observed: now.UTC().Format(time.RFC3339Nano), MembershipHash: ReconciliationMembershipDigest(m), Membership: m, MetadataOnly: true, CleanupRequired: true}
	if !ValidateReconciliationSnapshot(s, v, r, now) {
		return ReconciliationSnapshot{}, ErrCleanupContext
	}
	return s, nil
}

func ValidateReconciliationSnapshot(s ReconciliationSnapshot, v ReconcilerIdentity, r ReconciliationRequest, now time.Time) bool {
	m := s.Membership
	b := m.Binding.Document
	observed, err := time.Parse(time.RFC3339Nano, s.Observed)
	created, _ := time.Parse(time.RFC3339Nano, m.Created)
	if observed.Before(created) {
		return false
	}
	for _, w := range m.Workspaces {
		stamp, e := time.Parse(time.RFC3339Nano, w.Document.Created)
		if e != nil || stamp.After(observed) {
			return false
		}
	}
	for _, l := range m.Launches {
		stamp, e := time.Parse(time.RFC3339Nano, l.Document.Created)
		if e != nil || stamp.After(observed) {
			return false
		}
	}
	encoded, je := json.Marshal(s)
	return v.Valid(now) && r.Valid() && s.Schema == "1.0" && s.Reconciler == v.ID && s.Challenge == r.Challenge && s.MetadataOnly && s.CleanupRequired && !s.CleanupReleased && !s.EngineWrites && err == nil && !observed.After(now.Add(2*time.Second)) && !observed.Before(now.Add(-30*time.Second)) && je == nil && len(encoded) <= 63<<10 && m.Valid() && s.MembershipHash == ReconciliationMembershipDigest(m) && m.Owner == v.Owner && m.Job == r.Job && m.Generation.ID == r.Generation && m.Binding.Digest == v.Binding && b.Engine == v.Engine && b.Registry == v.Registry && b.Policy == v.Policy && b.Namespace == v.Namespace
}

func DecodeReconciliationSnapshot(b []byte) (ReconciliationSnapshot, error) {
	var s ReconciliationSnapshot
	if len(b) > 64<<10 || validateJSON(b) != nil || canonicalKeys(b, reflect.TypeOf(s)) != nil || json.Unmarshal(b, &s) != nil {
		return s, ErrCleanupContext
	}
	return s, nil
}
