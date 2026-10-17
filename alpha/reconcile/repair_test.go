// SPDX-License-Identifier: BUSL-1.1
package reconcile

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineobserve"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"strings"
	"testing"
)

type repairController struct {
	s    scanevidence.ReconciliationSnapshot
	sent *scanevidence.MutationRepairRequest
}

func (f *repairController) Snapshot(context.Context, string, string) (scanevidence.ReconciliationSnapshot, error) {
	return f.s, nil
}
func (f *repairController) Repair(_ context.Context, r scanevidence.MutationRepairRequest) (scanevidence.MutationRepairResult, error) {
	f.sent = &r
	return scanevidence.MutationRepairResult{Schema: "1.0"}, nil
}

type inspector struct {
	state   engineobserve.ContainerState
	err     error
	targets []engineobserve.Target
}

func (f *inspector) Inspect(_ context.Context, t engineobserve.Target) (engineobserve.ContainerState, error) {
	f.targets = append(f.targets, t)
	return f.state, f.err
}

const crashed = "aegis-scan-0123456789abcdef0123456789abcdef"

var engineX, engineY = strings.Repeat("e", 64), strings.Repeat("f", 64)

// crashedSnapshot adds one allocation's intents to the fixed sample. Repair
// sends whatever it derives to the controller, which revalidates membership;
// here only the runner's own decisions are under test.
func crashedSnapshot(t *testing.T, ops map[string]string) (scanevidence.ReconciliationSnapshot, map[string]scanevidence.MutationIntent) {
	t.Helper()
	s := snapshot(t)
	out := map[string]scanevidence.MutationIntent{}
	for _, op := range []string{"create", "start", "remove"} {
		state, ok := ops[op]
		if !ok {
			continue
		}
		target := ""
		if op != "create" {
			target = engineX
		}
		r := scanevidence.MutationRequest{Generation: s.Membership.Generation.ID, Job: s.Membership.Job, Tool: "bandit", Operation: op, Launch: source.Hash([]byte("launch")), Descriptor: source.Hash([]byte(op)), EngineID: target}
		m, err := scanevidence.NewMutationIntent(r, source.Hash([]byte("workspace")), crashed)
		if err != nil {
			t.Fatal(err)
		}
		if state == "completed" {
			m.State, m.Status, m.EngineID, m.Response = "completed", 204, engineX, source.Hash([]byte("response"))
			if op == "create" {
				m.Status = 201
			}
		}
		out[op] = m
		s.Membership.Mutations = append(s.Membership.Mutations, m)
	}
	return s, out
}

func sealedJournal(s scanevidence.ReconciliationSnapshot, intents map[string]scanevidence.MutationIntent) enginejournal.Evidence {
	b := s.Membership.Binding
	ev := enginejournal.Evidence{Policy: scanevidence.AdmittedJournalSeal(b.Document.Policy, b.Digest), Quarantine: enginejournal.QuarantineState{Sequence: 1, Quarantine: source.Hash([]byte("q")), Activation: source.Hash([]byte("a")), Attempts: []string{crashed}}, Attempt: enginejournal.AttemptEvidence{Name: crashed, Pending: map[string]enginejournal.PendingEvidence{}, Responses: map[string]enginejournal.ResponseEvidence{}, Repairs: map[string]enginejournal.RepairEvidenceEntry{}}}
	for op, m := range intents {
		proposed := m
		proposed.State, proposed.Status, proposed.EngineID, proposed.Response = "pending", 0, "", ""
		ev.Attempt.Pending[op] = enginejournal.PendingEvidence{Digest: source.Hash([]byte("pending " + op)), Controller: &proposed}
		if m.State == "completed" {
			ev.Attempt.Responses[op] = enginejournal.ResponseEvidence{Digest: source.Hash([]byte("response " + op)), Status: m.Status, Container: engineX}
		}
	}
	return ev
}

func runRepair(t *testing.T, s scanevidence.ReconciliationSnapshot, journal func(string) (enginejournal.Evidence, error), seen *inspector) (*repairController, error) {
	t.Helper()
	c := &repairController{s: s}
	_, err := Repair{Controller: c, Observer: seen, Journal: journal, Namespace: s.Membership.Binding.Document.Namespace}.Run(context.Background(), s.Membership.Job, s.Membership.Generation.ID)
	return c, err
}

func TestRepairMapsPositiveObservationsToOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ops      map[string]string
		answered string
		seen     engineobserve.ContainerState
		outcome  string
		engine   string
		targetID string
	}{
		{"create lost before engine", map[string]string{"create": "pending"}, "", engineobserve.ContainerState{}, scanevidence.RepairNotCreated, "", ""},
		{"create lost response", map[string]string{"create": "pending"}, "", engineobserve.ContainerState{Present: true, ID: engineY}, scanevidence.RepairCreated, engineY, ""},
		{"create lost acknowledgement", map[string]string{"create": "pending"}, "create", engineobserve.ContainerState{Present: true, ID: engineX}, scanevidence.RepairCreated, engineX, engineX},
		{"start never ran", map[string]string{"create": "completed", "start": "pending"}, "", engineobserve.ContainerState{Present: true, ID: engineX}, scanevidence.RepairNotStarted, engineX, engineX},
		{"start ran", map[string]string{"create": "completed", "start": "pending"}, "", engineobserve.ContainerState{Present: true, ID: engineX, Started: true}, scanevidence.RepairStarted, engineX, engineX},
		{"remove done", map[string]string{"create": "completed", "start": "completed", "remove": "pending"}, "", engineobserve.ContainerState{}, scanevidence.RepairRemoved, engineX, engineX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, intents := crashedSnapshot(t, tc.ops)
			ev := sealedJournal(s, intents)
			if tc.answered != "" {
				ev.Attempt.Responses[tc.answered] = enginejournal.ResponseEvidence{Digest: source.Hash([]byte("lost ack")), Status: 201, Container: engineX}
			}
			seen := &inspector{state: tc.seen}
			c, err := runRepair(t, s, func(string) (enginejournal.Evidence, error) { return ev, nil }, seen)
			if err != nil || c.sent == nil || len(c.sent.Resolutions) != 1 {
				t.Fatal("repair refused", err)
			}
			x := c.sent.Resolutions[0]
			if x.Outcome != tc.outcome || x.EngineID != tc.engine || !c.sent.Valid() || c.sent.Fence.Activation != ev.Quarantine.Activation || c.sent.Fence.Policy != ev.Policy {
				t.Fatal("wrong resolution", x)
			}
			if len(seen.targets) != 1 || seen.targets[0].Name != crashed || seen.targets[0].ID != tc.targetID {
				t.Fatal("observation was not exact", seen.targets)
			}
		})
	}
}

func TestRepairRefusesUnfencedUncertainOrContradictoryEvidence(t *testing.T) {
	s, intents := crashedSnapshot(t, map[string]string{"create": "pending"})
	good := sealedJournal(s, intents)
	clone := func(f func(*enginejournal.Evidence)) func(string) (enginejournal.Evidence, error) {
		return func(string) (enginejournal.Evidence, error) {
			ev := sealedJournal(s, intents)
			f(&ev)
			return ev, nil
		}
	}
	cases := map[string]struct {
		journal func(string) (enginejournal.Evidence, error)
		seen    *inspector
		want    error
	}{
		"no activation":       {clone(func(e *enginejournal.Evidence) { e.Quarantine.Activation = "" }), &inspector{}, ErrUnrepaired},
		"no quarantine":       {clone(func(e *enginejournal.Evidence) { e.Quarantine = enginejournal.QuarantineState{} }), &inspector{}, ErrUnrepaired},
		"other binding seal":  {clone(func(e *enginejournal.Evidence) { e.Policy = source.Hash([]byte("other")) }), &inspector{}, ErrUnrepaired},
		"attempt not sealed":  {clone(func(e *enginejournal.Evidence) { e.Quarantine.Attempts = []string{"aegis-scan-" + strings.Repeat("1", 32)} }), &inspector{}, ErrUnrepaired},
		"other proposal":      {clone(func(e *enginejournal.Evidence) { p := e.Attempt.Pending["create"]; c := *p.Controller; c.ID = source.Hash([]byte("x")); p.Controller = &c; e.Attempt.Pending["create"] = p }), &inspector{}, ErrUnrepaired},
		"no local proposal":   {clone(func(e *enginejournal.Evidence) { delete(e.Attempt.Pending, "create") }), &inspector{}, ErrUnrepaired},
		"already repaired":    {clone(func(e *enginejournal.Evidence) { e.Attempt.Repairs["create"] = enginejournal.RepairEvidenceEntry{} }), &inspector{}, ErrUnrepaired},
		"finished attempt":    {clone(func(e *enginejournal.Evidence) { e.Attempt.Finished = true }), &inspector{}, ErrUnrepaired},
		"journal unavailable": {func(string) (enginejournal.Evidence, error) { return good, enginejournal.ErrJournal }, &inspector{}, ErrUnrepaired},
		"observer uncertain":  {clone(func(*enginejournal.Evidence) {}), &inspector{err: engineobserve.ErrUnconfirmed}, ErrUnrepaired},
		"recorded 201 but gone": {clone(func(e *enginejournal.Evidence) {
			e.Attempt.Responses["create"] = enginejournal.ResponseEvidence{Digest: source.Hash([]byte("r")), Status: 201, Container: engineX}
		}), &inspector{}, ErrUnrepaired},
		"recorded 201, other id": {clone(func(e *enginejournal.Evidence) {
			e.Attempt.Responses["create"] = enginejournal.ResponseEvidence{Digest: source.Hash([]byte("r")), Status: 201, Container: engineX}
		}), &inspector{state: engineobserve.ContainerState{Present: true, ID: engineY}}, ErrUnrepaired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := runRepair(t, s, tc.journal, tc.seen)
			if err != tc.want || c.sent != nil {
				t.Fatal("unfenced or uncertain evidence repaired", err)
			}
		})
	}
	// A record appended while observing (a late plugin write) refuses.
	reads := 0
	changing := func(string) (enginejournal.Evidence, error) {
		reads++
		ev := sealedJournal(s, intents)
		if reads > 1 {
			ev.Attempt.Responses["create"] = enginejournal.ResponseEvidence{Digest: source.Hash([]byte("late")), Status: 201, Container: engineX}
		}
		return ev, nil
	}
	if c, err := runRepair(t, s, changing, &inspector{}); err != ErrUnrepaired || c.sent != nil {
		t.Fatal("journal change during observation ignored", err)
	}

	s, intents = crashedSnapshot(t, map[string]string{"create": "completed", "start": "pending"})
	ev := sealedJournal(s, intents)
	ev.Attempt.Responses["start"] = enginejournal.ResponseEvidence{Digest: source.Hash([]byte("started")), Status: 204, Container: engineX}
	if c, err := runRepair(t, s, func(string) (enginejournal.Evidence, error) { return ev, nil }, &inspector{state: engineobserve.ContainerState{Present: true, ID: engineX}}); err != ErrUnrepaired || c.sent != nil {
		t.Fatal("recorded start contradicted by a never-started container", err)
	}
	if c, err := runRepair(t, s, func(string) (enginejournal.Evidence, error) { return sealedJournal(s, intents), nil }, &inspector{}); err != ErrUnrepaired || c.sent != nil {
		t.Fatal("start repaired for a vanished container", err)
	}

	s, intents = crashedSnapshot(t, map[string]string{"create": "completed", "remove": "pending"})
	if c, err := runRepair(t, s, func(string) (enginejournal.Evidence, error) { return sealedJournal(s, intents), nil }, &inspector{state: engineobserve.ContainerState{Present: true, ID: engineX}}); err != ErrRemovalOutstanding || c.sent != nil {
		t.Fatal("present container repaired as removed", err)
	}
}
