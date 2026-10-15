// SPDX-License-Identifier: Apache-2.0
// Package enginejournal records local operator engine request uncertainty. A
// journal is not controller-authorized cleanup evidence or a release capability.
package enginejournal

import (
	"aegis.local/source"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"
)

var ErrJournal = errors.New("private engine journal unavailable or inconsistent")
var ErrPending = errors.New("engine request response remains unresolved")
var ErrFull = errors.New("engine journal retention budget reached")
var hash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var name = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)
var id = regexp.MustCompile(`^[0-9a-f]{64}$`)
var nonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

const maxAttempts = 1000
const maxBytes = 16 << 20

type identity struct {
	Schema    string `json:"schema_version"`
	Namespace string `json:"namespace_id"`
	Engine    string `json:"engine_digest"`
	Created   string `json:"created_at"`
}
type manifest struct {
	Schema     string `json:"schema_version"`
	Namespace  string `json:"namespace_digest"`
	Engine     string `json:"engine_digest"`
	Name       string `json:"container_name"`
	Descriptor string `json:"descriptor_digest"`
	Created    string `json:"created_at"`
}
type intent struct {
	Schema    string `json:"schema_version"`
	Manifest  string `json:"attempt_digest"`
	Previous  string `json:"previous_digest"`
	Operation string `json:"operation"`
	Container string `json:"container_id"`
	Created   string `json:"created_at"`
}
type response struct {
	Schema    string `json:"schema_version"`
	Intent    string `json:"intent_digest"`
	Operation string `json:"operation"`
	Status    int    `json:"response_status"`
	Container string `json:"container_id"`
	Created   string `json:"created_at"`
}
type envelope[T any] struct {
	Digest   string `json:"digest"`
	Document T      `json:"document"`
}

func wrapped[T any](d T) envelope[T] { b, _ := json.Marshal(d); return envelope[T]{source.Hash(b), d} }

type Observation struct {
	Schema            string `json:"schema_version"`
	Namespace         string `json:"namespace_digest"`
	Engine            string `json:"engine_digest"`
	Attempts          int    `json:"attempts"`
	Unfinished        int    `json:"unfinished_attempts"`
	Unresolved        int    `json:"unresolved_requests"`
	ControllerBound   bool   `json:"controller_gate_binding_verified"`
	ExclusiveOrigin   bool   `json:"all_engine_writes_mediated"`
	CleanupAuthorized bool   `json:"cleanup_release_authorized"`
}
type Journal struct {
	mu                                      sync.Mutex
	files                                   *privateRoot
	engine, namespace                       string
	attempts, unfinished, unresolved, bytes int
	closed                                  bool
	active                                  *Attempt
}
type Attempt struct {
	j                                 *Journal
	dir                               *privateRoot
	digest, name, container, previous string
	pending                           *Ticket
	begun                             map[string]bool
	complete                          map[string]bool
	closed                            bool
}
type Ticket struct {
	attempt           *Attempt
	operation, digest string
	done              bool
}

func (j *Journal) Observe() Observation {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Observation{Schema: "1.0", Namespace: j.namespace, Engine: j.engine, Attempts: j.attempts, Unresolved: j.unresolved, Unfinished: j.unfinished}
}
func (j *Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.closed {
		if j.active != nil {
			j.active.dir.close()
		}
		j.files.close()
		j.closed = true
	}
}
func (j *Journal) Begin(nameValue, descriptor string) (*Attempt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.active != nil || !name.MatchString(nameValue) || !hash.MatchString(descriptor) {
		return nil, ErrJournal
	}
	if j.unresolved != 0 || j.unfinished != 0 {
		return nil, ErrPending
	}
	if j.attempts >= maxAttempts {
		return nil, ErrFull
	}
	dir, e := j.files.newDir(nameValue)
	if e != nil {
		return nil, e
	}
	d := wrapped(manifest{Schema: "1.0", Namespace: j.namespace, Engine: j.engine, Name: nameValue, Descriptor: descriptor, Created: time.Now().UTC().Format(time.RFC3339Nano)})
	if e = j.write(dir, "attempt.json", d); e != nil {
		dir.close()
		return nil, e
	}
	a := &Attempt{j: j, dir: dir, digest: d.Digest, previous: d.Digest, name: nameValue, begun: map[string]bool{}, complete: map[string]bool{}}
	j.active = a
	j.attempts++
	j.unfinished++
	return a, nil
}
func (j *Journal) write(dir *privateRoot, path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil || len(b) > 4096 {
		return ErrJournal
	}
	if j.bytes+len(b)+1 > maxBytes {
		return ErrFull
	}
	if e = dir.write(path, append(b, '\n')); e != nil {
		return e
	}
	j.bytes += len(b) + 1
	return nil
}
func (a *Attempt) Begin(operation, container string) (*Ticket, error) {
	j := a.j
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || a.closed || j.active != a || a.pending != nil || j.unresolved != 0 || a.begun[operation] {
		return nil, ErrJournal
	}
	switch operation {
	case "create":
		if len(a.begun) != 0 || container != "" {
			return nil, ErrJournal
		}
	case "start":
		if !a.complete["create"] || a.begun["remove"] || container != a.container {
			return nil, ErrJournal
		}
	case "remove":
		if !a.complete["create"] || container != a.container {
			return nil, ErrJournal
		}
	default:
		return nil, ErrJournal
	}
	if operation != "create" && !id.MatchString(container) {
		return nil, ErrJournal
	}
	d := wrapped(intent{Schema: "1.0", Manifest: a.digest, Previous: a.previous, Operation: operation, Container: container, Created: time.Now().UTC().Format(time.RFC3339Nano)})
	if e := j.write(a.dir, operation+".pending.json", d); e != nil {
		return nil, e
	}
	ticket := &Ticket{attempt: a, operation: operation, digest: d.Digest}
	a.pending = ticket
	a.begun[operation] = true
	j.unresolved++
	return ticket, nil
}

// Confirm records an observed complete successful daemon response. Callers are
// trusted local code; this method cannot establish independent engine authority.
func (t *Ticket) Confirm(status int, container string) error {
	a := t.attempt
	j := a.j
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || a.closed || j.active != a || a.pending != t || t.done || !id.MatchString(container) {
		return ErrJournal
	}
	switch t.operation {
	case "create":
		if status != 201 {
			return ErrJournal
		}
	case "start":
		if status != 204 || container != a.container {
			return ErrJournal
		}
	case "remove":
		if (status != 204 && status != 404) || container != a.container {
			return ErrJournal
		}
	default:
		return ErrJournal
	}
	d := wrapped(response{Schema: "1.0", Intent: t.digest, Operation: t.operation, Status: status, Container: container, Created: time.Now().UTC().Format(time.RFC3339Nano)})
	if e := j.write(a.dir, t.operation+".response.json", d); e != nil {
		return e
	}
	a.previous = d.Digest
	t.done = true
	a.pending = nil
	a.complete[t.operation] = true
	j.unresolved--
	if t.operation == "create" {
		a.container = container
	}
	return nil
}
func (a *Attempt) Finish() error {
	j := a.j
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || a.closed || j.active != a {
		return ErrJournal
	}
	if a.pending != nil {
		return ErrPending
	}
	if !a.complete["remove"] {
		return ErrPending
	}
	a.closed = true
	a.dir.close()
	j.active = nil
	j.unfinished--
	return nil
}
