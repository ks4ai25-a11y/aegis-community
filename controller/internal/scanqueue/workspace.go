// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"database/sql"
	"encoding/json"
	"time"
)

const maxWorkspaceBytes = 4096

func workspaceTx(tx *sql.Tx, j Job, tool string) (scanevidence.WorkspaceRecord, error) {
	var doc, digest, owner, request, workspace, stamp string
	e := tx.QueryRow("SELECT document,digest,owner,request_digest,workspace,created_at FROM scanner_workspaces WHERE job=? AND tool=?", j.ID, tool).Scan(&doc, &digest, &owner, &request, &workspace, &stamp)
	if e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	var d scanevidence.Workspace
	if len(doc) > maxWorkspaceBytes || domain.Hash([]byte(doc)) != digest || json.Unmarshal([]byte(doc), &d) != nil || owner != j.Owner || request != j.RequestDigest || d.Schema != "1.0" || d.Owner != owner || d.Job != j.ID || d.Request != request || d.Plan.Tool != tool || d.Plan.Workspace != workspace || !workspaceID.MatchString(workspace) || !digestPattern.MatchString(d.Plan.Registry) || !digestPattern.MatchString(d.Plan.Snapshot) || d.App != j.Input.App || d.Repository != j.Input.Repository || d.Map != j.Input.MapDigest || d.Lock != j.LockDigest || d.Created != stamp {
		return scanevidence.WorkspaceRecord{}, ErrConflict
	}
	created, ce := time.Parse(time.RFC3339Nano, stamp)
	queued, qe := time.Parse(time.RFC3339Nano, j.Created)
	deadline, de := time.Parse(time.RFC3339, d.Deadline)
	if ce != nil || qe != nil || de != nil || created.Before(queued) || !created.Before(deadline) {
		return scanevidence.WorkspaceRecord{}, ErrConflict
	}
	return scanevidence.WorkspaceRecord{Digest: digest, Document: d}, nil
}

// ReserveWorkspace commits an immutable named intent before any run directory
// or source bytes exist. Exact replay still requires live authority. A lost
// acknowledgement retains admission and never proves allocation or absence.
func (q *Queue) ReserveWorkspace(l Lease, p scanevidence.WorkspacePlan) (scanevidence.WorkspaceRecord, error) {
	if !workspaceID.MatchString(p.Workspace) || !digestPattern.MatchString(p.Registry) || !digestPattern.MatchString(p.Snapshot) {
		return scanevidence.WorkspaceRecord{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	defer tx.Rollback()
	j, e := q.live(tx, l)
	if e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	if j.Owner != l.Job.Owner {
		return scanevidence.WorkspaceRecord{}, ErrLease
	}
	selected := false
	for _, tool := range j.Input.Tools {
		if tool == p.Tool {
			selected = true
		}
	}
	if !selected {
		return scanevidence.WorkspaceRecord{}, ErrInput
	}
	m, e := q.authority(tx, j)
	if e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	manifest := source.Manifest{Schema: "1.0", InputMap: m.Digest, Commit: m.Commit, Files: m.Files}
	for _, f := range m.Files {
		manifest.Bytes += f.Size
	}
	if domain.Digest(manifest) != p.Snapshot {
		return scanevidence.WorkspaceRecord{}, ErrInput
	}
	old, e := workspaceTx(tx, j, p.Tool)
	if e == nil {
		if old.Document.Plan != p {
			return scanevidence.WorkspaceRecord{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return scanevidence.WorkspaceRecord{}, e
	}
	var priorTool string
	e = tx.QueryRow("SELECT tool FROM scanner_workspaces WHERE job=? ORDER BY tool LIMIT 1", j.ID).Scan(&priorTool)
	if e == nil {
		prior, err := workspaceTx(tx, j, priorTool)
		if err != nil {
			return scanevidence.WorkspaceRecord{}, err
		}
		if prior.Document.Plan.Registry != p.Registry {
			return scanevidence.WorkspaceRecord{}, ErrConflict
		}
	} else if e != sql.ErrNoRows {
		return scanevidence.WorkspaceRecord{}, e
	}
	var n int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_workspaces WHERE workspace=?", p.Workspace).Scan(&n); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	if n != 0 {
		return scanevidence.WorkspaceRecord{}, ErrConflict
	}
	if e = tx.QueryRow("SELECT count(*) FROM scanner_workspaces").Scan(&n); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	if n >= 6000 {
		return scanevidence.WorkspaceRecord{}, ErrFull
	}
	var deadline int64
	if e = tx.QueryRow("SELECT deadline FROM scanner_dispatch WHERE job=?", j.ID).Scan(&deadline); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	stamp := q.now().UTC().Format(time.RFC3339Nano)
	if _, e = q.live(tx, l); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	created, ce := time.Parse(time.RFC3339Nano, stamp)
	queued, qe := time.Parse(time.RFC3339Nano, j.Created)
	if ce != nil || qe != nil || created.Before(queued) || !created.Before(time.Unix(deadline, 0)) {
		return scanevidence.WorkspaceRecord{}, ErrLease
	}
	d := scanevidence.Workspace{Schema: "1.0", Owner: j.Owner, Job: j.ID, Request: j.RequestDigest, App: j.Input.App, Repository: j.Input.Repository, Map: j.Input.MapDigest, Lock: j.LockDigest, Plan: p, Created: stamp, Deadline: time.Unix(deadline, 0).UTC().Format(time.RFC3339)}
	b, e := json.Marshal(d)
	if e != nil || len(b) > maxWorkspaceBytes {
		return scanevidence.WorkspaceRecord{}, ErrInput
	}
	hash := domain.Hash(b)
	if _, e = tx.Exec("INSERT INTO scanner_workspaces VALUES(?,?,?,?,?,?,?,?)", j.ID, p.Tool, j.Owner, j.RequestDigest, p.Workspace, hash, string(b), stamp); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	if e = store.AuditTx(tx, j.Owner, "scanner.workspace", j.ID, "reserved", map[string]any{"tool_id": p.Tool, "workspace_digest": hash, "request_digest": j.RequestDigest, "workspace_id": p.Workspace, "registry_digest": p.Registry, "cleanup_confirmed": false}); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	return scanevidence.WorkspaceRecord{Digest: hash, Document: d}, nil
}

// Workspaces reads known reservations only. An empty list is not evidence that
// a legacy or unsupported worker created no artifacts in a trusted namespace.
func (q *Queue) Workspaces(owner, id string) ([]scanevidence.WorkspaceRecord, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, owner))
	if e != nil {
		return nil, e
	}
	rows, e := tx.Query("SELECT tool FROM scanner_workspaces WHERE job=? ORDER BY tool", id)
	if e != nil {
		return nil, e
	}
	var tools []string
	for rows.Next() {
		var tool string
		if e = rows.Scan(&tool); e != nil {
			rows.Close()
			return nil, e
		}
		if len(tools) >= 6 {
			rows.Close()
			return nil, ErrConflict
		}
		tools = append(tools, tool)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []scanevidence.WorkspaceRecord{}
	for _, tool := range tools {
		selected := false
		for _, allowed := range j.Input.Tools {
			if tool == allowed {
				selected = true
			}
		}
		if !selected {
			return nil, ErrConflict
		}
		record, e := workspaceTx(tx, j, tool)
		if e != nil {
			return nil, e
		}
		out = append(out, record)
	}
	return out, nil
}

func matchWorkspaceTx(tx *sql.Tx, j Job, p scanevidence.LaunchPlan, created string) error {
	r, e := workspaceTx(tx, j, p.Tool)
	if e == sql.ErrNoRows {
		return ErrConflict
	}
	if e != nil {
		return e
	}
	d := r.Document
	stamp, se := time.Parse(time.RFC3339Nano, created)
	reserved, re := time.Parse(time.RFC3339Nano, d.Created)
	if d.Plan.Workspace != p.Workspace || d.Plan.Registry != p.Registry || d.Plan.Snapshot != p.Snapshot || se != nil || re != nil || stamp.Before(reserved) {
		return ErrConflict
	}
	return nil
}
