// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/source/scanevidence"
	"context"
	"net/url"
	"strings"
	"time"
)

// Sealed quarantine serving (ADR 057 crash repair).
//
// A crashed admitted plugin leaves one unfinished attempt; Open then refuses
// admitted serving. Quarantine serving opens the same journal under the same
// sealed admitted policy and binding, and writes a quarantine seal while it
// holds the journal's exclusive lifetime lock. It allows reads only, never a
// create or start, and the normal admitted removal of the tracked allocation
// once the controller has retained a repair for every earlier obligation.
//
// Why an in-flight Allow cannot complete after repair: the admitted plugin
// replies Allow only from a process that holds the journal lock, and the seal
// proves no such process remains. An Allow already sent lives only in the
// daemon process that received it; Docker activates a legacy plugin once per
// daemon process, so the activation recorded under the seal proves a daemon
// process started after the seal. A repair is accepted only after that record
// exists, so every observation it relies on was made after any daemon process
// that could hold an earlier Allow had stopped. This assumes the dedicated
// daemon runs as a single process for its data root, as dockerd enforces with
// its pidfile; it is the reason the operator must restart that daemon.

func (p *Policy) activated() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quarantine && !p.closed {
		_, _ = p.journal.RecordActivation()
	}
}

// resumeRemove prepares the quarantined attempt for the broker's exact
// removal of its tracked allocation. resumed means an already admitted,
// still pending removal is being carried out for the first time under the
// fence; otherwise the caller continues with the normal admitted removal.
func (p *Policy) resumeRemove(ctx context.Context, r Request, u *url.URL) (resumed, ok bool) {
	engineID := strings.TrimPrefix(u.Path, api+"/containers/")
	if p.admitted == nil || r.RequestMethod != "DELETE" || len(r.RequestBody) != 0 || !idPattern.MatchString(engineID) || !exactQuery(u, url.Values{"force": {"1"}, "v": {"1"}}) {
		return false, false
	}
	attempt, open := p.journal.OpenAttempt()
	if !open {
		return false, false
	}
	// Settle earlier pending operations from retained controller repairs.
	for range 3 {
		operation, intent, e := p.journal.PendingOperation(attempt)
		if e != nil || operation == "" || operation == "remove" {
			break
		}
		read, e := p.admitted.client.Intent(ctx, intent.Request.Generation, intent.ID)
		if e != nil || !read.Found || read.Intent.State != "repaired" || read.Repair == nil {
			return false, false
		}
		outcome := read.Repair.Resolution.Outcome
		if operation == "create" && (outcome != scanevidence.RepairCreated || read.Intent.EngineID != engineID) || operation == "start" && read.Intent.EngineID != engineID {
			return false, false
		}
		if p.journal.RecordRepair(attempt, operation, outcome, read.Intent.EngineID, read.Repair.Digest) != nil {
			return false, false
		}
	}
	operation, intent, e := p.journal.PendingOperation(attempt)
	if e != nil || operation != "" && operation != "remove" {
		return false, false
	}
	var pendingRemove *scanevidence.MutationIntent
	if operation == "remove" {
		// The removal was admitted but never answered. Under the fence the
		// daemon that received any earlier Allow is gone, so if the
		// allocation still exists this is its first effective execution.
		read, e := p.admitted.client.Intent(ctx, intent.Request.Generation, intent.ID)
		if e != nil || !read.Found || read.Intent.State != "pending" || read.Intent.Request != intent.Request || read.Intent.Request.EngineID != engineID {
			return false, false
		}
		pendingRemove = read.Intent
	}
	a, e := p.journal.Resume(attempt)
	if e != nil {
		return false, false
	}
	if a.Container() != engineID || a.Controller() == nil {
		p.journal.Release(a)
		return false, false
	}
	p.attempt, p.name, p.id, p.mutation, p.createBody = a, attempt, engineID, *a.Controller(), nil
	if pendingRemove == nil {
		return false, true
	}
	p.ticket = a.PendingTicket()
	p.pending = fingerprint(r)
	p.operation = "remove"
	p.mutation = *pendingRemove
	return true, p.ticket != nil
}

// SettleQuarantine runs offline, holding the journal lock, after the daemon
// restart recorded an activation. It writes a local repair record for each
// pending operation the controller has resolved, and records a create the
// controller never admitted under a closed generation as not admitted. It
// returns the journal observation; only zero unfinished attempts is settled.
func SettleQuarantine(c Config) (enginejournal.Observation, enginejournal.QuarantineState, error) {
	if c.Admitted == nil {
		return enginejournal.Observation{}, enginejournal.QuarantineState{}, ErrPolicy
	}
	j, e := enginejournal.OpenExisting(c.JournalRoot, c.EngineDigest)
	if e != nil {
		return enginejournal.Observation{}, enginejournal.QuarantineState{}, ErrPolicy
	}
	defer j.Close()
	gate, e := openAdmitted(c, *c.Admitted)
	if e != nil {
		return enginejournal.Observation{}, enginejournal.QuarantineState{}, ErrPolicy
	}
	defer gate.client.Close()
	if j.Observe().Attempts == 0 || j.RequirePolicy(gate.seal) != nil {
		return enginejournal.Observation{}, enginejournal.QuarantineState{}, ErrPolicy
	}
	q := j.Quarantine()
	if q.Sequence == 0 || q.Activation == "" {
		return j.Observe(), q, enginejournal.ErrQuarantine
	}
	attempt, open := j.OpenAttempt()
	if !open {
		return j.Observe(), q, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 3 {
		operation, intent, e := j.PendingOperation(attempt)
		if e != nil || operation == "" {
			break
		}
		read, e := gate.client.Intent(ctx, intent.Request.Generation, intent.ID)
		if e != nil {
			return j.Observe(), q, ErrPolicy
		}
		switch {
		case !read.Found && operation == "create":
			e = j.RecordRepair(attempt, operation, "not_admitted", "", "")
		case read.Found && read.Intent.State == "repaired" && read.Repair != nil:
			e = j.RecordRepair(attempt, operation, read.Repair.Resolution.Outcome, read.Intent.EngineID, read.Repair.Digest)
		default:
			// Still pending or natively completed without a local response:
			// nothing here may settle it.
			return j.Observe(), q, enginejournal.ErrQuarantine
		}
		if e != nil {
			return j.Observe(), q, ErrPolicy
		}
	}
	return j.Observe(), j.Quarantine(), nil
}
