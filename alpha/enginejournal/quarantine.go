// SPDX-License-Identifier: BUSL-1.1
package enginejournal

import (
	"aegis.local/source/scanevidence"
	"errors"
	"regexp"
)

// Sealed quarantine (ADR 057 crash repair). An admitted plugin cannot reopen
// a journal with an unfinished attempt. A quarantine-serving plugin may, but
// it first writes quarantine.N.json while holding the journal's exclusive
// lifetime lock: no admitted plugin process is serving this namespace when
// that record is written, and none can serve it again until every listed
// attempt is finished. activation.N.json then records the first daemon
// plugin activation the quarantine plugin received: a daemon process started
// after the seal, so no daemon process holding an earlier Allow survives.
// Only after both may an attempt's pending operation be resolved by an
// explicit repair record, mirroring a retained controller repair. These are
// local records; the controller and an independent observer decide repair.

var ErrQuarantine = errors.New("engine journal quarantine unavailable or unfenced")

const maxQuarantines = 64

var jobPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var sealRecord = regexp.MustCompile(`^(quarantine|activation)\.([1-9][0-9]?)\.json$`)

type quarantine struct {
	Schema    string   `json:"schema_version"`
	Namespace string   `json:"namespace_digest"`
	Engine    string   `json:"engine_digest"`
	Policy    string   `json:"local_policy_digest"`
	Sequence  int      `json:"sequence"`
	Attempts  []string `json:"unfinished_attempts"`
	Created   string   `json:"created_at"`
}

type activation struct {
	Schema     string `json:"schema_version"`
	Quarantine string `json:"quarantine_digest"`
	Sequence   int    `json:"sequence"`
	Created    string `json:"created_at"`
}

const (
	repairCreated     = scanevidence.RepairCreated
	repairNotCreated  = scanevidence.RepairNotCreated
	repairStarted     = scanevidence.RepairStarted
	repairNotStarted  = scanevidence.RepairNotStarted
	repairRemoved     = scanevidence.RepairRemoved
	repairNotAdmitted = "not_admitted"
)

// repairRecord replies to one pending operation in place of a native
// response. Controller is the retained controller repair digest; it is empty
// only for not_admitted, when the controller holds no such intent under a
// closed generation, so the proposed admission can never commit.
type repairRecord struct {
	Schema     string `json:"schema_version"`
	Intent     string `json:"intent_digest"`
	Operation  string `json:"operation"`
	Outcome    string `json:"outcome"`
	Container  string `json:"container_id"`
	Controller string `json:"controller_repair_digest"`
	Quarantine string `json:"quarantine_digest"`
	Activation string `json:"activation_digest"`
	Created    string `json:"created_at"`
}

// releaseRecord closes an attempt in an unbound (broker) journal after the
// controller retained an independent cleanup confirmation that observed this
// exact container absent. It never answers the open operation; it records
// that the authoritative release no longer depends on that answer.
type releaseRecord struct {
	Schema       string `json:"schema_version"`
	Manifest     string `json:"attempt_digest"`
	Previous     string `json:"previous_digest"`
	Job          string `json:"job_id"`
	Generation   string `json:"generation_id"`
	Container    string `json:"container_name"`
	EngineID     string `json:"engine_id"`
	Confirmation string `json:"confirmation_digest"`
	Created      string `json:"created_at"`
}

type attemptState struct {
	released                              bool
	name, manifest, previous, known, open string
	controller                            *scanevidence.MutationIntent
	pending                               map[string]envelope[intent]
	responses                             map[string]envelope[response]
	repairs                               map[string]envelope[repairRecord]
	finished                              bool
	bytes                                 int
}

// QuarantineState is local bookkeeping for status and the plugin's own use.
type QuarantineState struct {
	Sequence   int      `json:"sequence"`
	Quarantine string   `json:"quarantine_digest"`
	Activation string   `json:"activation_digest"`
	Attempts   []string `json:"unfinished_attempts"`
}

// Quarantine reports the latest seal, if any. Sequence 0 means none.
func (j *Journal) Quarantine() QuarantineState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.quarantineLocked()
}

func (j *Journal) quarantineLocked() QuarantineState {
	if len(j.quarantines) == 0 {
		return QuarantineState{}
	}
	q := j.quarantines[len(j.quarantines)-1]
	out := QuarantineState{Sequence: q.Document.Sequence, Quarantine: q.Digest, Attempts: append([]string(nil), q.Document.Attempts...)}
	if a, ok := j.activations[q.Document.Sequence]; ok {
		out.Activation = a.Digest
	}
	return out
}

// OpenAttempt names the single unfinished attempt, if any. The journal
// refuses a new attempt while one is unfinished, so there is at most one.
func (j *Journal) OpenAttempt() (string, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.openAttempts) != 1 {
		return "", false
	}
	return j.openAttempts[0], true
}

// Evidence is a lock-free, read-only view of the sealed journal for an
// independent reconciler. It is local plugin bookkeeping: it can corroborate
// or contradict an engine observation, never replace one.
type Evidence struct {
	Namespace  string          `json:"namespace_digest"`
	Engine     string          `json:"engine_digest"`
	Policy     string          `json:"local_policy_digest"`
	Quarantine QuarantineState `json:"quarantine"`
	Attempt    AttemptEvidence `json:"attempt"`
}

type AttemptEvidence struct {
	Name      string                         `json:"container_name"`
	Known     string                         `json:"container_id"`
	Open      string                         `json:"open_operation"`
	Finished  bool                           `json:"finished"`
	Pending   map[string]PendingEvidence     `json:"pending"`
	Responses map[string]ResponseEvidence    `json:"responses"`
	Repairs   map[string]RepairEvidenceEntry `json:"repairs"`
}

type PendingEvidence struct {
	Digest     string                       `json:"digest"`
	Controller *scanevidence.MutationIntent `json:"controller_intent"`
}

type ResponseEvidence struct {
	Digest    string `json:"digest"`
	Status    int    `json:"status"`
	Container string `json:"container_id"`
}

type RepairEvidenceEntry struct {
	Digest     string `json:"digest"`
	Outcome    string `json:"outcome"`
	Container  string `json:"container_id"`
	Controller string `json:"controller_repair_digest"`
}
