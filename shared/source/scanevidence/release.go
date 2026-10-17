// SPDX-License-Identifier: BUSL-1.1
package scanevidence

import (
	"errors"
	"sort"
	"time"
)

// Independent cleanup confirmation and release (ADR 057). A reconciler with
// its own enrollment reads the complete retained membership, holds the
// original workspace registry empty under its namespace barrier, observes the
// original engine read-only, and asks the controller to release. The
// controller recomputes membership in the release transaction; nothing in
// this request is trusted to select which obligations exist.

var ErrNotReleasable = errors.New("allocation not releasable")

// CleanupAbsence is one exact allocation observed absent from the original
// engine. EngineID is empty only for a launch whose create was never admitted.
type CleanupAbsence struct {
	Tool      string `json:"tool_id"`
	Container string `json:"container"`
	EngineID  string `json:"engine_id"`
}

type CleanupConfirmationRequest struct {
	Job        string           `json:"job_id"`
	Generation string           `json:"generation_id"`
	Membership string           `json:"membership_digest"`
	Engine     string           `json:"engine_digest"`
	Namespace  string           `json:"registry_namespace_digest"`
	Absent     []CleanupAbsence `json:"absent"`
}

type CleanupConfirmation struct {
	Schema     string                     `json:"schema_version"`
	Reconciler string                     `json:"reconciler_id"`
	Request    CleanupConfirmationRequest `json:"request"`
	Confirmed  string                     `json:"confirmed_at"`
	Released   bool                       `json:"dispatch_released"`
	Digest     string                     `json:"confirmation_digest"`
}

func (r CleanupConfirmationRequest) Valid() bool {
	if !cleanupJob.MatchString(r.Job) || !allocationID.MatchString(r.Generation) || !hash.MatchString(r.Membership) || !hash.MatchString(r.Engine) || !hash.MatchString(r.Namespace) || r.Absent == nil || len(r.Absent) > 6 {
		return false
	}
	for i, a := range r.Absent {
		if !container.MatchString(a.Container) || a.Tool == "" || len(a.Tool) > 32 || (a.EngineID != "" && !allocationID.MatchString(a.EngineID)) || (i > 0 && r.Absent[i-1].Tool >= a.Tool) {
			return false
		}
	}
	return true
}

// RequiredAbsences derives, from complete retained membership, every
// allocation that must be observed absent before release. It refuses when any
// obligation is unresolved: a pending mutation, a confirmed create without a
// confirmed removal, or a start/remove without a confirmed create. A create
// repaired as not created leaves only its exact name to observe absent; a
// create repaired as created needs a settled removal like a native one.
func RequiredAbsences(m ReconciliationMembership) ([]CleanupAbsence, error) {
	if !m.Valid() {
		return nil, ErrNotReleasable
	}
	type ops struct{ create, start, remove *MutationIntent }
	byTool := map[string]*ops{}
	for i := range m.Mutations {
		x := &m.Mutations[i]
		if !x.Settled() {
			return nil, ErrNotReleasable
		}
		o := byTool[x.Request.Tool]
		if o == nil {
			o = &ops{}
			byTool[x.Request.Tool] = o
		}
		switch x.Request.Operation {
		case "create":
			o.create = x
		case "start":
			o.start = x
		case "remove":
			o.remove = x
		default:
			return nil, ErrNotReleasable
		}
	}
	out := []CleanupAbsence{}
	launched := map[string]bool{}
	for _, l := range m.Launches {
		tool, name := l.Document.Plan.Tool, l.Document.Plan.Container
		launched[tool] = true
		o := byTool[tool]
		switch {
		case o == nil || o.create == nil || o.create.State == "repaired" && o.create.EngineID == "":
			if o != nil && (o.start != nil || o.remove != nil) || o != nil && o.create != nil && o.create.Container != name {
				return nil, ErrNotReleasable
			}
			out = append(out, CleanupAbsence{Tool: tool, Container: name})
		// The removal (and any start) must target exactly the created engine
		// ID; a removal of some other container proves nothing about this one.
		case o.remove == nil || o.create.EngineID == "" || o.create.Container != name || o.remove.Container != name || o.remove.Request.EngineID != o.create.EngineID || (o.start != nil && (o.start.Request.EngineID != o.create.EngineID || o.start.Container != name)):
			return nil, ErrNotReleasable
		default:
			out = append(out, CleanupAbsence{Tool: tool, Container: name, EngineID: o.create.EngineID})
		}
	}
	// Obligations without a launch cannot be resolved by an exact observation.
	for tool := range byTool {
		if !launched[tool] {
			return nil, ErrNotReleasable
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out, nil
}

func NewCleanupConfirmation(reconciler string, r CleanupConfirmationRequest, now time.Time) CleanupConfirmation {
	c := CleanupConfirmation{Schema: "1.0", Reconciler: reconciler, Request: r, Confirmed: now.UTC().Format(time.RFC3339Nano), Released: true}
	c.Digest = digest(struct {
		Schema, Reconciler string
		Request            CleanupConfirmationRequest
		Confirmed          string
	}{c.Schema, c.Reconciler, c.Request, c.Confirmed})
	return c
}
