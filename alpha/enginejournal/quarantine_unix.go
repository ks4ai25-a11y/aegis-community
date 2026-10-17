// SPDX-License-Identifier: BUSL-1.1
//go:build linux || darwin

package enginejournal

import (
	"aegis.local/source/scanevidence"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

// loadQuarantines validates the contiguous seal and activation records. Each
// seal names the attempts that were unfinished when it was written.
func (j *Journal) loadQuarantines(p *privateRoot, items []os.DirEntry) error {
	seqs := map[string]map[int]bool{"quarantine": {}, "activation": {}}
	for _, item := range items {
		m := sealRecord.FindStringSubmatch(item.Name())
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		seqs[m[1]][n] = true
	}
	total := len(seqs["quarantine"])
	if total > maxQuarantines {
		return ErrJournal
	}
	for n := 1; n <= total; n++ {
		if !seqs["quarantine"][n] {
			return ErrJournal
		}
	}
	for n := range seqs["activation"] {
		if !seqs["quarantine"][n] {
			return ErrJournal
		}
	}
	j.quarantines, j.activations = nil, map[int]envelope[activation]{}
	var earlier time.Time
	for n := 1; n <= total; n++ {
		q, size, e := read[quarantine](p, fmt.Sprintf("quarantine.%d.json", n))
		j.bytes += size
		d := q.Document
		at, te := time.Parse(time.RFC3339Nano, d.Created)
		if e != nil || te != nil || at.Before(earlier) || d.Schema != "1.0" || d.Namespace != j.namespace || d.Engine != j.engine || j.policy == "" || d.Policy != j.policy || d.Sequence != n || len(d.Attempts) < 1 || len(d.Attempts) > maxAttempts || !sort.StringsAreSorted(d.Attempts) {
			return ErrJournal
		}
		for i, a := range d.Attempts {
			if !name.MatchString(a) || i > 0 && d.Attempts[i-1] == a {
				return ErrJournal
			}
		}
		earlier = at
		j.quarantines = append(j.quarantines, q)
		if !seqs["activation"][n] {
			continue
		}
		a, size, e := read[activation](p, fmt.Sprintf("activation.%d.json", n))
		j.bytes += size
		activated, ae := time.Parse(time.RFC3339Nano, a.Document.Created)
		if e != nil || ae != nil || activated.Before(at) || a.Document.Schema != "1.0" || a.Document.Quarantine != q.Digest || a.Document.Sequence != n {
			return ErrJournal
		}
		j.activations[n] = a
	}
	return nil
}

// validRepair checks a repair record against its pending operation and the
// sealed, activated quarantine that must list this attempt.
func (j *Journal) validRepair(d repairRecord, pending, op, attempt, known string, stamp time.Time) bool {
	at, e := time.Parse(time.RFC3339Nano, d.Created)
	if e != nil || at.Before(stamp) || d.Schema != "1.0" || d.Intent != pending || d.Operation != op {
		return false
	}
	listed := false
	for _, q := range j.quarantines {
		if q.Digest != d.Quarantine {
			continue
		}
		a, ok := j.activations[q.Document.Sequence]
		if !ok || a.Digest != d.Activation || at.Before(time.Time{}) {
			return false
		}
		activated, _ := time.Parse(time.RFC3339Nano, a.Document.Created)
		if at.Before(activated) {
			return false
		}
		for _, x := range q.Document.Attempts {
			listed = listed || x == attempt
		}
	}
	if !listed || (d.Outcome == repairNotAdmitted) != (d.Controller == "") || d.Controller != "" && !hash.MatchString(d.Controller) {
		return false
	}
	switch d.Outcome {
	case repairCreated:
		return op == "create" && id.MatchString(d.Container)
	case repairNotCreated, repairNotAdmitted:
		return op == "create" && d.Container == ""
	case repairStarted, repairNotStarted:
		return op == "start" && d.Container == known
	case repairRemoved:
		return op == "remove" && d.Container == known
	}
	return false
}

// SealQuarantine records that this process, holding the exclusive journal
// lock, found unfinished attempts. A repeated start reuses the open seal.
func (j *Journal) SealQuarantine() (QuarantineState, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.policy == "" || j.active != nil || len(j.openAttempts) == 0 {
		return QuarantineState{}, ErrQuarantine
	}
	current := append([]string(nil), j.openAttempts...)
	sort.Strings(current)
	if len(j.quarantines) != 0 {
		latest := j.quarantines[len(j.quarantines)-1].Document.Attempts
		sealed, overlap := map[string]bool{}, false
		for _, a := range latest {
			sealed[a] = true
		}
		covered := true
		for _, a := range current {
			covered = covered && sealed[a]
			overlap = overlap || sealed[a]
		}
		if covered {
			return j.quarantineLocked(), nil
		}
		if overlap {
			return QuarantineState{}, ErrQuarantine
		}
	}
	if len(j.quarantines) >= maxQuarantines {
		return QuarantineState{}, ErrFull
	}
	n := len(j.quarantines) + 1
	d := wrapped(quarantine{Schema: "1.0", Namespace: j.namespace, Engine: j.engine, Policy: j.policy, Sequence: n, Attempts: current, Created: time.Now().UTC().Format(time.RFC3339Nano)})
	if e := j.write(j.files, fmt.Sprintf("quarantine.%d.json", n), d); e != nil {
		return QuarantineState{}, e
	}
	j.quarantines = append(j.quarantines, d)
	return j.quarantineLocked(), nil
}

// RecordActivation records the first daemon plugin activation received after
// the latest seal. The daemon activates a legacy plugin once per process, so
// this proves a daemon process started after the admitting plugin stopped.
func (j *Journal) RecordActivation() (QuarantineState, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || len(j.quarantines) == 0 {
		return QuarantineState{}, ErrQuarantine
	}
	q := j.quarantines[len(j.quarantines)-1]
	n := q.Document.Sequence
	if _, ok := j.activations[n]; ok {
		return j.quarantineLocked(), nil
	}
	d := wrapped(activation{Schema: "1.0", Quarantine: q.Digest, Sequence: n, Created: time.Now().UTC().Format(time.RFC3339Nano)})
	if e := j.write(j.files, fmt.Sprintf("activation.%d.json", n), d); e != nil {
		return QuarantineState{}, e
	}
	j.activations[n] = d
	return j.quarantineLocked(), nil
}

// fencedAttempt opens an unfinished attempt listed by the latest activated
// seal. Callers hold j.mu.
func (j *Journal) fencedAttempt(attempt string) (*privateRoot, attemptState, error) {
	q := j.quarantineLocked()
	listed, open := false, false
	for _, a := range q.Attempts {
		listed = listed || a == attempt
	}
	for _, a := range j.openAttempts {
		open = open || a == attempt
	}
	if j.closed || j.active != nil || q.Activation == "" || !listed || !open {
		return nil, attemptState{}, ErrQuarantine
	}
	before, e := j.files.root.Lstat(attempt)
	if e != nil || !owned(before, 0700, true) {
		return nil, attemptState{}, ErrJournal
	}
	root, e := j.files.root.OpenRoot(attempt)
	if e != nil {
		return nil, attemptState{}, ErrJournal
	}
	child := &privateRoot{root: root}
	after, e := root.Stat(".")
	if e != nil || !owned(after, 0700, true) || !os.SameFile(before, after) {
		child.close()
		return nil, attemptState{}, ErrJournal
	}
	st, e := j.inspectAttempt(child, attempt)
	if e != nil || st.finished {
		child.close()
		return nil, attemptState{}, ErrJournal
	}
	return child, st, nil
}

// PendingOperation reports an open attempt's unanswered operation and the
// controller intent its pending record proposed, so a quarantined plugin can
// ask the controller how that intent was resolved.
func (j *Journal) PendingOperation(attempt string) (string, *scanevidence.MutationIntent, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	child, st, e := j.fencedAttempt(attempt)
	if e != nil {
		return "", nil, e
	}
	child.close()
	if st.open == "" {
		return "", nil, nil
	}
	c := st.pending[st.open].Document.Controller
	if c == nil {
		return "", nil, ErrQuarantine
	}
	copy := *c
	return st.open, &copy, nil
}

// RecordRepair answers the attempt's single pending operation with an
// explicit repair, never a native response. It is written only under an
// activated seal, for the exact outcome the controller retained.
func (j *Journal) RecordRepair(attempt, operation, outcome, container, controller string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	child, st, e := j.fencedAttempt(attempt)
	if e != nil {
		return e
	}
	defer child.close()
	if st.open != operation {
		return ErrQuarantine
	}
	q := j.quarantineLocked()
	pending := st.pending[operation]
	stamp, _ := time.Parse(time.RFC3339Nano, pending.Document.Created)
	d := repairRecord{Schema: "1.0", Intent: pending.Digest, Operation: operation, Outcome: outcome, Container: container, Controller: controller, Quarantine: q.Quarantine, Activation: q.Activation, Created: time.Now().UTC().Format(time.RFC3339Nano)}
	if !j.validRepair(d, pending.Digest, operation, attempt, st.known, stamp) {
		return ErrQuarantine
	}
	if e = j.write(child, operation+".repair.json", wrapped(d)); e != nil {
		return e
	}
	j.unresolved--
	switch outcome {
	case repairCreated:
		j.rememberContainer(attempt, container)
	case repairNotCreated, repairNotAdmitted, repairRemoved:
		j.finishedLocked(attempt)
	}
	return nil
}

func (j *Journal) finishedLocked(attempt string) {
	j.unfinished--
	kept := j.openAttempts[:0]
	for _, a := range j.openAttempts {
		if a != attempt {
			kept = append(kept, a)
		}
	}
	j.openAttempts = kept
}

// Resume reopens the fenced unfinished attempt so a quarantined plugin can
// carry its normal admitted removal. An unanswered pending operation becomes
// the attempt's pending ticket; nothing is executed or written here.
func (j *Journal) Resume(attempt string) (*Attempt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	child, st, e := j.fencedAttempt(attempt)
	if e != nil {
		return nil, e
	}
	a := &Attempt{controller: st.controller, j: j, dir: child, digest: st.manifest, previous: st.previous, name: attempt, container: st.known, begun: map[string]bool{}, complete: map[string]bool{}}
	for op := range st.pending {
		a.begun[op] = true
	}
	for op := range st.responses {
		a.complete[op] = true
	}
	for op := range st.repairs {
		a.complete[op] = true
	}
	if st.open != "" {
		a.pending = &Ticket{attempt: a, operation: st.open, digest: st.pending[st.open].Digest}
	}
	j.active = a
	return a, nil
}

// ReadEvidence reads one attempt and the seals without taking the journal
// lock, which the serving quarantine plugin holds. Records are written once,
// synced and digest-checked, so a partial write fails closed here.
func ReadEvidence(path, engine, attempt string) (Evidence, error) {
	if os.Geteuid() <= 0 || !hash.MatchString(engine) || !name.MatchString(attempt) {
		return Evidence{}, ErrJournal
	}
	p, e := openPrivate(path)
	if e != nil {
		return Evidence{}, e
	}
	defer p.close()
	ident, _, e := read[identity](p, "identity.json")
	if e != nil || ident.Document.Schema != "1.0" || ident.Document.Engine != engine || !nonce.MatchString(ident.Document.Namespace) {
		return Evidence{}, ErrJournal
	}
	policy, _, e := read[localPolicy](p, "policy.json")
	if e != nil || policy.Document.Schema != "1.0" || policy.Document.Namespace != ident.Digest || policy.Document.Engine != engine || !hash.MatchString(policy.Document.Policy) {
		return Evidence{}, ErrJournal
	}
	j := &Journal{files: p, engine: engine, namespace: ident.Digest, policy: policy.Document.Policy}
	items, e := p.list(maxAttempts + 3 + 2*maxQuarantines)
	if e != nil {
		return Evidence{}, e
	}
	if e = j.loadQuarantines(p, items); e != nil {
		return Evidence{}, e
	}
	before, e := p.root.Lstat(attempt)
	if e != nil || !owned(before, 0700, true) {
		return Evidence{}, ErrJournal
	}
	root, e := p.root.OpenRoot(attempt)
	if e != nil {
		return Evidence{}, ErrJournal
	}
	child := &privateRoot{root: root}
	defer child.close()
	after, e := root.Stat(".")
	if e != nil || !owned(after, 0700, true) || !os.SameFile(before, after) {
		return Evidence{}, ErrJournal
	}
	st, e := j.inspectAttempt(child, attempt)
	if e != nil {
		return Evidence{}, e
	}
	out := Evidence{Namespace: ident.Digest, Engine: engine, Policy: policy.Document.Policy, Quarantine: j.quarantineLocked(), Attempt: AttemptEvidence{Name: attempt, Known: st.known, Open: st.open, Finished: st.finished, Pending: map[string]PendingEvidence{}, Responses: map[string]ResponseEvidence{}, Repairs: map[string]RepairEvidenceEntry{}}}
	for op, x := range st.pending {
		out.Attempt.Pending[op] = PendingEvidence{Digest: x.Digest, Controller: x.Document.Controller}
	}
	for op, x := range st.responses {
		out.Attempt.Responses[op] = ResponseEvidence{Digest: x.Digest, Status: x.Document.Status, Container: x.Document.Container}
	}
	for op, x := range st.repairs {
		out.Attempt.Repairs[op] = RepairEvidenceEntry{Digest: x.Digest, Outcome: x.Document.Outcome, Container: x.Document.Container, Controller: x.Document.Controller}
	}
	return out, nil
}

func (j *Journal) validRelease(d releaseRecord, st attemptState) bool {
	_, e := time.Parse(time.RFC3339Nano, d.Created)
	return e == nil && j.policy == "" && d.Schema == "1.0" && d.Manifest == st.manifest && d.Previous == st.previous && d.Container == st.name && (st.known == "" || d.EngineID == st.known) && (d.EngineID == "" || id.MatchString(d.EngineID)) && hash.MatchString(d.Confirmation) && jobPattern.MatchString(d.Job) && id.MatchString(d.Generation)
}

// SettleReleased closes the single unfinished attempt of an unbound broker
// journal from the controller's retained cleanup confirmation for exactly that
// container. The caller holds the journal lock, so no worker is running.
func (j *Journal) SettleReleased(attempt string, c scanevidence.CleanupConfirmation) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	open := false
	for _, a := range j.openAttempts {
		open = open || a == attempt
	}
	absence, covered := c.Absence(attempt)
	if j.closed || j.policy != "" || j.active != nil || !open || !covered || !hash.MatchString(c.Digest) {
		return ErrQuarantine
	}
	before, e := j.files.root.Lstat(attempt)
	if e != nil || !owned(before, 0700, true) {
		return ErrJournal
	}
	root, e := j.files.root.OpenRoot(attempt)
	if e != nil {
		return ErrJournal
	}
	child := &privateRoot{root: root}
	defer child.close()
	after, e := root.Stat(".")
	if e != nil || !owned(after, 0700, true) || !os.SameFile(before, after) {
		return ErrJournal
	}
	st, e := j.inspectAttempt(child, attempt)
	if e != nil || st.finished {
		return ErrJournal
	}
	d := releaseRecord{Schema: "1.0", Manifest: st.manifest, Previous: st.previous, Job: c.Request.Job, Generation: c.Request.Generation, Container: attempt, EngineID: absence.EngineID, Confirmation: c.Digest, Created: time.Now().UTC().Format(time.RFC3339Nano)}
	if !j.validRelease(d, st) {
		return ErrQuarantine
	}
	if e = j.write(child, "release.json", wrapped(d)); e != nil {
		return e
	}
	if st.open != "" {
		j.unresolved--
	}
	j.finishedLocked(attempt)
	return nil
}
