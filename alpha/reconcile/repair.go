// SPDX-License-Identifier: BUSL-1.1
package reconcile

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineobserve"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"errors"
	"reflect"
)

// ErrUnrepaired means nothing was repaired: the fence, the journal or an
// observation was missing, uncertain or contradictory. Quarantine stays.
var ErrUnrepaired = errors.New("scanner mutation repair refused; quarantine retained")

// ErrRemovalOutstanding means a pending removal's container is still present.
// Resume that removal through the quarantined plugin, then repair again.
var ErrRemovalOutstanding = errors.New("scanner removal outstanding; resume it through the quarantined plugin")

type RepairController interface {
	Snapshot(ctx context.Context, job, generation string) (scanevidence.ReconciliationSnapshot, error)
	Repair(ctx context.Context, r scanevidence.MutationRepairRequest) (scanevidence.MutationRepairResult, error)
}

type Inspector interface {
	Inspect(ctx context.Context, target engineobserve.Target) (engineobserve.ContainerState, error)
}

// JournalReader reads the sealed plugin journal for one attempt, read-only.
type JournalReader func(attempt string) (enginejournal.Evidence, error)

// Repair resolves every pending intent of one closed generation (ADR 057
// sealed crash repair). It requires the plugin journal sealed in quarantine
// and activated by a daemon started after the seal, bound to this exact
// binding; it then observes the original engine read-only and maps each
// pending intent to exactly one positive outcome, or refuses everything.
type Repair struct {
	Controller RepairController
	Observer   Inspector
	Journal    JournalReader
	Namespace  string
}

type observation struct {
	Present bool   `json:"present"`
	ID      string `json:"engine_id"`
	Started bool   `json:"started"`
}

func (r Repair) Run(ctx context.Context, job, generation string) (scanevidence.MutationRepairResult, error) {
	if r.Controller == nil || r.Observer == nil || r.Journal == nil || r.Namespace == "" {
		return scanevidence.MutationRepairResult{}, ErrUnrepaired
	}
	s, err := r.Controller.Snapshot(ctx, job, generation)
	if err != nil {
		return scanevidence.MutationRepairResult{}, ErrUnrepaired
	}
	m := s.Membership
	b := m.Binding.Document
	pending := scanevidence.PendingIntents(m)
	if b.Namespace != r.Namespace || len(pending) == 0 {
		return scanevidence.MutationRepairResult{}, ErrUnrepaired
	}
	// The journal admits one attempt at a time, so all pending obligations
	// belong to one allocation.
	name := pending[0].Container
	settled := map[string]scanevidence.MutationIntent{}
	for _, x := range m.Mutations {
		if x.Container != name && x.State == "pending" {
			return scanevidence.MutationRepairResult{}, ErrUnrepaired
		}
		if x.Container == name && x.Settled() {
			settled[x.Request.Operation] = x
		}
	}
	seal := scanevidence.AdmittedJournalSeal(b.Policy, m.Binding.Digest)
	before, err := r.fenced(name, seal)
	if err != nil {
		return scanevidence.MutationRepairResult{}, err
	}
	fence := scanevidence.RepairFence{Policy: seal, Quarantine: before.Quarantine.Quarantine, Activation: before.Quarantine.Activation}
	req := scanevidence.MutationRepairRequest{Job: m.Job, Generation: m.Generation.ID, Membership: s.MembershipHash, Engine: b.Engine, Namespace: b.Namespace, Fence: fence}
	for _, p := range pending {
		op := p.Request.Operation
		local, ok := before.Attempt.Pending[op]
		if !ok || local.Controller == nil || local.Controller.ID != p.ID || local.Controller.Request != p.Request || local.Controller.Workspace != p.Workspace {
			return scanevidence.MutationRepairResult{}, ErrUnrepaired
		}
		if _, repaired := before.Attempt.Repairs[op]; repaired {
			return scanevidence.MutationRepairResult{}, ErrUnrepaired
		}
		response, answered := before.Attempt.Responses[op]
		target := engineobserve.Target{Name: name, ID: p.Request.EngineID}
		if op == "create" {
			target.ID = ""
			if answered {
				target.ID = response.Container
			}
		} else if created := settled["create"]; created.EngineID == "" || created.EngineID != p.Request.EngineID {
			return scanevidence.MutationRepairResult{}, ErrUnrepaired
		}
		seen, err := r.Observer.Inspect(ctx, target)
		if err != nil {
			return scanevidence.MutationRepairResult{}, ErrUnrepaired
		}
		x := scanevidence.MutationResolution{Intent: p.ID, Operation: op}
		switch op {
		case "create":
			switch {
			case seen.Present && (!answered || response.Container == seen.ID):
				x.Outcome, x.EngineID = scanevidence.RepairCreated, seen.ID
			case !seen.Present && !answered:
				x.Outcome = scanevidence.RepairNotCreated
			default:
				// A recorded 201 whose container is gone was removed by no
				// admitted removal: contradictory.
				return scanevidence.MutationRepairResult{}, ErrUnrepaired
			}
		case "start":
			if !seen.Present || seen.ID != p.Request.EngineID || answered && !seen.Started {
				return scanevidence.MutationRepairResult{}, ErrUnrepaired
			}
			x.Outcome, x.EngineID = scanevidence.RepairNotStarted, p.Request.EngineID
			if seen.Started {
				x.Outcome = scanevidence.RepairStarted
			}
		case "remove":
			if seen.Present {
				if answered {
					return scanevidence.MutationRepairResult{}, ErrUnrepaired
				}
				return scanevidence.MutationRepairResult{}, ErrRemovalOutstanding
			}
			x.Outcome, x.EngineID = scanevidence.RepairRemoved, p.Request.EngineID
		default:
			return scanevidence.MutationRepairResult{}, ErrUnrepaired
		}
		evidence, _ := json.Marshal(struct {
			Domain, Quarantine, Activation, Pending, Response string
			Observed                                          observation
		}{"aegis-scanner-repair-evidence-v1", fence.Quarantine, fence.Activation, local.Digest, response.Digest, observation{seen.Present, seen.ID, seen.Started}})
		x.Evidence = source.Hash(evidence)
		req.Resolutions = append(req.Resolutions, x)
	}
	// The sealed records are append-only. Any change while observing (for
	// example a late response written by a plugin) refuses the repair.
	after, err := r.fenced(name, seal)
	if err != nil || !reflect.DeepEqual(before, after) {
		return scanevidence.MutationRepairResult{}, ErrUnrepaired
	}
	out, err := r.Controller.Repair(ctx, req)
	if err != nil {
		return scanevidence.MutationRepairResult{}, ErrUnrepaired
	}
	return out, nil
}

// fenced reads the journal and requires the quarantine fence: the admitted
// seal of this binding, a quarantine listing this attempt, and an activation
// by a daemon started after that quarantine.
func (r Repair) fenced(name, seal string) (enginejournal.Evidence, error) {
	ev, err := r.Journal(name)
	if err != nil || ev.Policy != seal || ev.Quarantine.Sequence == 0 || ev.Quarantine.Quarantine == "" || ev.Quarantine.Activation == "" || ev.Attempt.Name != name || ev.Attempt.Finished {
		return enginejournal.Evidence{}, ErrUnrepaired
	}
	listed := false
	for _, a := range ev.Quarantine.Attempts {
		listed = listed || a == name
	}
	if !listed {
		return enginejournal.Evidence{}, ErrUnrepaired
	}
	return ev, nil
}
