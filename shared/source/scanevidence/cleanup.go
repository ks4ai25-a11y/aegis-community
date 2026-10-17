// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"aegis.local/source"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

const CleanupObserverRole = "scanner-cleanup-observer"

var ErrCleanupContext = errors.New("scanner cleanup metadata context rejected")
var cleanupJob = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var cleanupWorkspace = regexp.MustCompile(`^run-[0-9a-f]{32}$`)
var cleanupIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type VerifierIdentity struct {
	Schema   string `json:"schema_version"`
	Role     string `json:"role"`
	ID       string `json:"verifier_id"`
	Owner    string `json:"owner_id"`
	Engine   string `json:"engine_digest"`
	Registry string `json:"registry_digest"`
	State    string `json:"state"`
	Expires  string `json:"expires_at"`
	Created  string `json:"created_at"`
}
type CleanupContext struct {
	Schema            string            `json:"schema_version"`
	Verifier          string            `json:"verifier_id"`
	Owner             string            `json:"owner_id"`
	Job               string            `json:"job_id"`
	Request           string            `json:"request_digest"`
	App               string            `json:"app_id"`
	Repository        string            `json:"repository_id"`
	Map               string            `json:"map_digest"`
	Lock              string            `json:"tool_lock_digest"`
	Created           string            `json:"job_created_at"`
	Worker            string            `json:"worker_id"`
	JobState          string            `json:"job_state"`
	CancelRequested   bool              `json:"cancel_requested"`
	DispatchState     string            `json:"dispatch_state"`
	Deadline          string            `json:"deadline"`
	LeaseUntil        string            `json:"lease_expires_at"`
	GuardSet          string            `json:"guard_set_digest"`
	Engine            string            `json:"engine_digest"`
	Registry          string            `json:"registry_digest"`
	Tools             []string          `json:"tool_ids"`
	Workspaces        []WorkspaceRecord `json:"workspaces"`
	Launches          []LaunchRecord    `json:"launches"`
	Observed          string            `json:"observed_at"`
	MetadataOnly      bool              `json:"controller_metadata_only"`
	CleanupRequired   bool              `json:"cleanup_required"`
	CleanupConfirmed  bool              `json:"cleanup_confirmed"`
	LeasesExcluded    bool              `json:"active_workspace_leases_excluded"`
	LateStartExcluded bool              `json:"late_start_excluded"`
}
type CleanupContextRecord struct {
	Digest   string         `json:"context_digest"`
	Document CleanupContext `json:"document"`
}

func NewCleanupContext(d CleanupContext) (CleanupContextRecord, error) {
	b, e := json.Marshal(d)
	if e != nil || len(b) > 48<<10 {
		return CleanupContextRecord{}, ErrCleanupContext
	}
	r := CleanupContextRecord{Digest: source.Hash(b), Document: d}
	if ValidateCleanupContext(r, d.Owner, d.Verifier, d.Job, d.Engine, d.Registry, d.Lock) != nil {
		return CleanupContextRecord{}, ErrCleanupContext
	}
	return r, nil
}

// ValidateCleanupContext validates metadata identity, never host cleanup.
func ValidateCleanupContext(r CleanupContextRecord, owner, verifier, job, engine, registry, lock string) error {
	d := r.Document
	b, e := json.Marshal(d)
	created, ce := time.Parse(time.RFC3339Nano, d.Created)
	observed, oe := time.Parse(time.RFC3339Nano, d.Observed)
	deadline, de := time.Parse(time.RFC3339, d.Deadline)
	lease, le := time.Parse(time.RFC3339, d.LeaseUntil)
	if e != nil || len(b) > 48<<10 || source.Hash(b) != r.Digest || d.Schema != "1.0" || d.Owner != owner || owner == "" || len(owner) > 128 || d.Verifier != verifier || !cleanupIdentity.MatchString(verifier) || d.Job != job || !cleanupJob.MatchString(job) || !hash.MatchString(d.Request) || d.App != "app_demo" || d.Repository == "" || len(d.Repository) > 128 || !hash.MatchString(d.Map) || d.Lock != lock || !hash.MatchString(lock) || d.Engine != engine || !hash.MatchString(engine) || d.Registry != registry || !hash.MatchString(registry) || !hash.MatchString(d.GuardSet) || !cleanupIdentity.MatchString(d.Worker) || ce != nil || oe != nil || de != nil || le != nil || observed.Before(created) || !deadline.After(created) || lease.After(deadline) || lease.IsZero() || !d.MetadataOnly || !d.CleanupRequired || d.CleanupConfirmed || d.LeasesExcluded || d.LateStartExcluded || len(d.Tools) < 1 || len(d.Tools) > 6 || !sort.StringsAreSorted(d.Tools) || len(d.Workspaces) < 1 || len(d.Workspaces) > 6 || len(d.Launches) < 1 || len(d.Launches) > 6 {
		return ErrCleanupContext
	}
	switch d.JobState {
	case "running", "cancelled", "timeout", "failed", "completed", "completed_partial", "completed_stale_db", "tool_error":
	default:
		return ErrCleanupContext
	}
	if d.DispatchState != "active" && d.DispatchState != "cleanup_required" {
		return ErrCleanupContext
	}
	selected := map[string]bool{}
	for _, t := range d.Tools {
		if selected[t] {
			return ErrCleanupContext
		}
		if _, e := BuildInvocation(t); e != nil {
			return ErrCleanupContext
		}
		selected[t] = true
	}
	workspaces := map[string]WorkspaceRecord{}
	workspaceIDs := map[string]bool{}
	previous := ""
	snapshot := ""
	for _, r := range d.Workspaces {
		w := r.Document
		raw, e := json.Marshal(w)
		stamp, se := time.Parse(time.RFC3339Nano, w.Created)
		if e != nil || len(raw) > 4096 || source.Hash(raw) != r.Digest || w.Schema != "1.0" || w.Owner != owner || w.Job != job || w.Request != d.Request || w.App != d.App || w.Repository != d.Repository || w.Map != d.Map || w.Lock != d.Lock || w.Deadline != d.Deadline || se != nil || stamp.Before(created) || stamp.After(observed) || !stamp.Before(deadline) || !selected[w.Plan.Tool] || w.Plan.Tool <= previous || w.Plan.Registry != registry || !hash.MatchString(w.Plan.Snapshot) || !cleanupWorkspace.MatchString(w.Plan.Workspace) || workspaceIDs[w.Plan.Workspace] {
			return ErrCleanupContext
		}
		if snapshot != "" && w.Plan.Snapshot != snapshot {
			return ErrCleanupContext
		}
		snapshot = w.Plan.Snapshot
		workspaces[w.Plan.Tool] = r
		workspaceIDs[w.Plan.Workspace] = true
		previous = w.Plan.Tool
	}
	containers := map[string]bool{}
	previous = ""
	for _, r := range d.Launches {
		l := r.Document
		w, ok := workspaces[l.Plan.Tool]
		raw, e := json.Marshal(l)
		stamp, se := time.Parse(time.RFC3339Nano, l.Created)
		reserved, re := time.Parse(time.RFC3339Nano, w.Document.Created)
		if !ok || e != nil || len(raw) > 4096 || source.Hash(raw) != r.Digest || !GuardedLaunchRevision(l) || l.GuardSet != d.GuardSet || l.GuardProtocol != GuardProtocol || !hash.MatchString(l.Plan.Guard) || (l.Plan.Architecture != "amd64" && l.Plan.Architecture != "arm64") || l.Owner != owner || l.Job != job || l.Request != d.Request || l.App != d.App || l.Repository != d.Repository || l.Map != d.Map || l.Lock != d.Lock || l.Deadline != d.Deadline || se != nil || re != nil || stamp.Before(reserved) || stamp.After(observed) || !stamp.Before(deadline) || l.Profile != "repo_offline-network-none-v1" || l.Duration < 1 || l.Duration > 120 || l.Version == "" || len(l.Version) > 64 || !hash.MatchString(l.Image) || !selected[l.Plan.Tool] || l.Plan.Tool <= previous || l.Plan.Engine != engine || l.Plan.Registry != registry || l.Plan.Workspace != w.Document.Plan.Workspace || l.Plan.Snapshot != snapshot || !container.MatchString(l.Plan.Container) || containers[l.Plan.Container] {
			return ErrCleanupContext
		}
		containers[l.Plan.Container] = true
		previous = l.Plan.Tool
	}
	return nil
}

func ValidateVerifierIdentity(v VerifierIdentity, owner, id, engine, registry string, now time.Time) error {
	created, ce := time.Parse(time.RFC3339Nano, v.Created)
	expires, ee := time.Parse(time.RFC3339, v.Expires)
	if v.Schema != "1.0" || v.Role != CleanupObserverRole || v.Owner != owner || owner == "" || len(owner) > 128 || v.ID != id || !cleanupIdentity.MatchString(id) || v.Engine != engine || !hash.MatchString(engine) || v.Registry != registry || !hash.MatchString(registry) || v.State != "active" || ce != nil || ee != nil || created.After(now.Add(2*time.Second)) || !expires.After(created) || !expires.After(now) || expires.Sub(created) > 24*time.Hour {
		return ErrCleanupContext
	}
	return nil
}
