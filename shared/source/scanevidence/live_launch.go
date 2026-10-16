// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var ErrLiveLaunch = errors.New("live scanner launch observation rejected")
var liveChallenge = regexp.MustCompile(`^[0-9a-f]{32}$`)

// LiveLaunchContext is a fresh read of controller state, not an engine write or
// cleanup capability. Its consumer must still enforce profile/bytes and check
// authority again at each relevant daemon mutation.
type LiveLaunchContext struct {
	Schema            string               `json:"schema_version"`
	Challenge         string               `json:"challenge"`
	Container         string               `json:"container_name"`
	Context           CleanupContextRecord `json:"context"`
	EngineBinding     EngineBindingRecord  `json:"engine_binding"`
	JournalBinding    JournalBindingRecord `json:"journal_binding"`
	BrokerBinding     BrokerBindingRecord  `json:"broker_binding"`
	Live              bool                 `json:"live_lease_observed"`
	MetadataOnly      bool                 `json:"controller_metadata_only"`
	EngineAuthorized  bool                 `json:"engine_write_authorized"`
	CleanupAuthorized bool                 `json:"cleanup_release_authorized"`
}
type LiveLaunchRecord struct {
	Digest   string            `json:"observation_digest"`
	Document LiveLaunchContext `json:"document"`
}

func NewLiveLaunch(d LiveLaunchContext) (LiveLaunchRecord, error) {
	r := LiveLaunchRecord{Digest: digest(d), Document: d}
	c := d.Context.Document
	if ValidateLiveLaunch(r, c.Owner, c.Verifier, d.Container, d.Challenge, c.Engine, c.Registry, c.Lock) != nil {
		return LiveLaunchRecord{}, ErrLiveLaunch
	}
	return r, nil
}
func ValidateLiveLaunch(r LiveLaunchRecord, owner, verifier, name, challenge, engine, registry, lock string) error {
	d := r.Document
	c := d.Context.Document
	raw, e := json.Marshal(d)
	if e != nil || len(raw) > 60<<10 || r.Digest != digest(d) || d.Schema != "1.0" || d.Container != name || !container.MatchString(name) || d.Challenge != challenge || !liveChallenge.MatchString(challenge) || !d.Live || !d.MetadataOnly || d.EngineAuthorized || d.CleanupAuthorized {
		return ErrLiveLaunch
	}
	if ValidateCleanupContext(d.Context, owner, verifier, c.Job, engine, registry, lock) != nil || c.JobState != "running" || c.CancelRequested || c.DispatchState != "active" {
		return ErrLiveLaunch
	}
	if !d.BrokerBinding.Valid(owner, d.EngineBinding, d.JournalBinding) || d.EngineBinding.Document.Engine != engine || d.EngineBinding.Document.Registry != registry || d.BrokerBinding.Document.Worker != c.Worker {
		return ErrLiveLaunch
	}
	observed, oe := time.Parse(time.RFC3339Nano, c.Observed)
	lease, le := time.Parse(time.RFC3339, c.LeaseUntil)
	deadline, de := time.Parse(time.RFC3339, c.Deadline)
	if oe != nil || le != nil || de != nil || !lease.After(observed) || !deadline.After(observed) {
		return ErrLiveLaunch
	}
	for _, created := range []string{d.EngineBinding.Document.Created, d.JournalBinding.Document.Created, d.BrokerBinding.Document.Created} {
		stamp, e := time.Parse(time.RFC3339Nano, created)
		if e != nil || stamp.After(observed) {
			return ErrLiveLaunch
		}
	}
	found := 0
	for _, launch := range c.Launches {
		p := launch.Document.Plan
		if launch.Document.Schema != "1.2" || p.JournalBinding != d.JournalBinding.Digest || p.JournalNamespace != d.JournalBinding.Document.Namespace {
			return ErrLiveLaunch
		}
		if p.Container == name {
			found++
		}
	}
	if found != 1 {
		return ErrLiveLaunch
	}
	return nil
}
