// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrContextScope = errors.New("scanner cleanup context outside enrolled scope")
var ErrContextUnbound = errors.New("scanner cleanup context is incomplete or legacy")

// CleanupContext is metadata only. The private handler authenticates the
// credential; this transaction independently rechecks enrollment and scope.
func (q *Queue) CleanupContext(ctx context.Context, v scanevidence.VerifierIdentity, id string) (scanevidence.CleanupContextRecord, error) {
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	defer tx.Rollback()
	now := q.now().UTC()
	if e = scannerauth.AuthorizeVerifierTx(tx, v, now.Unix()); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	j, e := read(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, v.Owner))
	if e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	d := scanevidence.CleanupContext{Schema: "1.0", Verifier: v.ID, Owner: v.Owner, Job: j.ID, Request: j.RequestDigest, App: j.Input.App, Repository: j.Input.Repository, Map: j.Input.MapDigest, Lock: j.LockDigest, Created: j.Created, JobState: j.State, CancelRequested: j.CancelRequested, Engine: v.Engine, Registry: v.Registry, Tools: append([]string{}, j.Input.Tools...), Workspaces: []scanevidence.WorkspaceRecord{}, Launches: []scanevidence.LaunchRecord{}, Observed: now.Format(time.RFC3339Nano), MetadataOnly: true, CleanupRequired: true}
	var lease, deadline int64
	var launchProtocol, workspaceProtocol int
	if e = tx.QueryRowContext(ctx, "SELECT worker,lease_until,deadline,state,launch_protocol,workspace_protocol,guard_set_digest FROM scanner_dispatch WHERE job=?", id).Scan(&d.Worker, &lease, &deadline, &d.DispatchState, &launchProtocol, &workspaceProtocol, &d.GuardSet); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	if launchProtocol != 1 || workspaceProtocol != 1 || !digestPattern.MatchString(d.GuardSet) {
		return scanevidence.CleanupContextRecord{}, ErrContextUnbound
	}
	d.Deadline = time.Unix(deadline, 0).UTC().Format(time.RFC3339)
	d.LeaseUntil = time.Unix(lease, 0).UTC().Format(time.RFC3339)
	rows, e := tx.QueryContext(ctx, "SELECT tool FROM scanner_workspaces WHERE job=? UNION SELECT tool FROM scanner_launches WHERE job=? ORDER BY tool", id, id)
	if e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	var recorded []string
	for rows.Next() {
		var tool string
		if e = rows.Scan(&tool); e != nil {
			rows.Close()
			return scanevidence.CleanupContextRecord{}, e
		}
		if len(recorded) >= 6 {
			rows.Close()
			return scanevidence.CleanupContextRecord{}, ErrConflict
		}
		recorded = append(recorded, tool)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	selected := map[string]bool{}
	for _, tool := range j.Input.Tools {
		selected[tool] = true
	}
	for _, tool := range recorded {
		if !selected[tool] {
			return scanevidence.CleanupContextRecord{}, ErrConflict
		}
		w, e := workspaceTx(tx, j, tool)
		if e != nil {
			if e == sql.ErrNoRows {
				return scanevidence.CleanupContextRecord{}, ErrConflict
			}
			return scanevidence.CleanupContextRecord{}, e
		}
		if w.Document.Plan.Registry != v.Registry {
			return scanevidence.CleanupContextRecord{}, ErrContextScope
		}
		d.Workspaces = append(d.Workspaces, w)
		l, e := launchTx(tx, j, tool)
		if e == sql.ErrNoRows {
			continue
		}
		if e != nil {
			return scanevidence.CleanupContextRecord{}, e
		}
		if l.Document.Plan.Registry != v.Registry || l.Document.Plan.Engine != v.Engine {
			return scanevidence.CleanupContextRecord{}, ErrContextScope
		}
		if l.Document.Schema != "1.1" {
			return scanevidence.CleanupContextRecord{}, ErrContextUnbound
		}
		if e = matchWorkspaceTx(tx, j, l.Document.Plan, l.Document.Created); e != nil {
			return scanevidence.CleanupContextRecord{}, e
		}
		d.Launches = append(d.Launches, l)
	}
	if len(d.Launches) == 0 || len(d.Workspaces) == 0 {
		return scanevidence.CleanupContextRecord{}, ErrContextUnbound
	}
	if e = ctx.Err(); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	if e = scannerauth.AuthorizeVerifierTx(tx, v, q.now().Unix()); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	out, e := scanevidence.NewCleanupContext(d)
	if e != nil {
		return scanevidence.CleanupContextRecord{}, ErrConflict
	}
	b, e := json.Marshal(out)
	if e != nil || len(b) > 49<<10 {
		return scanevidence.CleanupContextRecord{}, ErrConflict
	}
	return out, nil
}
