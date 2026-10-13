// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"database/sql"
	"encoding/json"
	"regexp"
	"time"
)

var containerID = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)
var workspaceID = regexp.MustCompile(`^run-[0-9a-f]{32}$`)

const maxLaunchBytes = 4096

func decodeLaunch(doc, digest, owner, job, request, tool, container, workspace, created string) (scanevidence.LaunchRecord, error) {
	var d scanevidence.Launch
	if len(doc) > maxLaunchBytes || domain.Hash([]byte(doc)) != digest || json.Unmarshal([]byte(doc), &d) != nil || d.Schema != "1.0" || d.Owner != owner || d.Job != job || d.Request != request || d.Plan.Tool != tool || d.Plan.Container != container || d.Plan.Workspace != workspace || d.Created != created || !containerID.MatchString(container) || !workspaceID.MatchString(workspace) || !digestPattern.MatchString(d.Plan.Engine) || !digestPattern.MatchString(d.Plan.Registry) || !digestPattern.MatchString(d.Plan.Snapshot) {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	stamp, e := time.Parse(time.RFC3339Nano, created)
	if e != nil {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	deadline, e := time.Parse(time.RFC3339, d.Deadline)
	if e != nil || !deadline.After(stamp) {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	return scanevidence.LaunchRecord{Digest: digest, Document: d}, nil
}

func launchTx(tx *sql.Tx, j Job, tool string) (scanevidence.LaunchRecord, error) {
	var doc, digest, owner, request, container, workspace, stamp string
	e := tx.QueryRow("SELECT document,digest,owner,request_digest,container,workspace,created_at FROM scanner_launches WHERE job=? AND tool=?", j.ID, tool).Scan(&doc, &digest, &owner, &request, &container, &workspace, &stamp)
	if e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	if owner != j.Owner || request != j.RequestDigest {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	r, e := decodeLaunch(doc, digest, owner, j.ID, request, tool, container, workspace, stamp)
	if e != nil {
		return r, e
	}
	d := r.Document
	created, ce := time.Parse(time.RFC3339Nano, d.Created)
	queued, qe := time.Parse(time.RFC3339Nano, j.Created)
	if ce != nil || qe != nil || created.Before(queued) {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	if d.App != j.Input.App || d.Repository != j.Input.Repository || d.Map != j.Input.MapDigest || d.Lock != j.LockDigest || d.Profile != "repo_offline-network-none-v1" || d.Duration != j.Input.Duration || !digestPattern.MatchString(d.Image) || d.Version == "" || len(d.Version) > 64 {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	return r, nil
}

// RegisterLaunch commits before execution. Even exact replay requires a live
// lease: a historic acknowledgement must never authorize a late Docker start.
func (q *Queue) RegisterLaunch(l Lease, p scanevidence.LaunchPlan) (scanevidence.LaunchRecord, error) {
	if !containerID.MatchString(p.Container) || !workspaceID.MatchString(p.Workspace) || !digestPattern.MatchString(p.Engine) || !digestPattern.MatchString(p.Registry) || !digestPattern.MatchString(p.Snapshot) {
		return scanevidence.LaunchRecord{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	defer tx.Rollback()
	j, e := q.live(tx, l)
	if e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	if j.Owner != l.Job.Owner {
		return scanevidence.LaunchRecord{}, ErrLease
	}
	selected := false
	for _, tool := range j.Input.Tools {
		if tool == p.Tool {
			selected = true
		}
	}
	pin, ok := q.Pins[p.Tool]
	if !selected || !ok || pin.Version == "" || len(pin.Version) > 64 || !digestPattern.MatchString(pin.Image) {
		return scanevidence.LaunchRecord{}, ErrInput
	}
	m, e := q.authority(tx, j)
	if e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	manifest := source.Manifest{Schema: "1.0", InputMap: m.Digest, Commit: m.Commit, Files: m.Files}
	for _, f := range m.Files {
		manifest.Bytes += f.Size
	}
	if domain.Digest(manifest) != p.Snapshot {
		return scanevidence.LaunchRecord{}, ErrInput
	}
	if e = matchWorkspaceTx(tx, j, p, q.now().UTC().Format(time.RFC3339Nano)); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	old, e := launchTx(tx, j, p.Tool)
	if e == nil {
		if old.Document.Plan != p || old.Document.Version != pin.Version || old.Document.Image != pin.Image {
			return scanevidence.LaunchRecord{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return scanevidence.LaunchRecord{}, e
	}
	var priorTool string
	e = tx.QueryRow("SELECT tool FROM scanner_launches WHERE job=? ORDER BY tool LIMIT 1", j.ID).Scan(&priorTool)
	if e == nil {
		prior, err := launchTx(tx, j, priorTool)
		if err != nil {
			return scanevidence.LaunchRecord{}, err
		}
		if prior.Document.Plan.Engine != p.Engine || prior.Document.Plan.Registry != p.Registry {
			return scanevidence.LaunchRecord{}, ErrConflict
		}
	} else if e != sql.ErrNoRows {
		return scanevidence.LaunchRecord{}, e
	}
	var n int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_launches WHERE container=? OR workspace=?", p.Container, p.Workspace).Scan(&n); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	if n != 0 {
		return scanevidence.LaunchRecord{}, ErrConflict
	}
	if e = tx.QueryRow("SELECT count(*) FROM scanner_launches").Scan(&n); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	if n >= 6000 {
		return scanevidence.LaunchRecord{}, ErrFull
	}
	var deadline int64
	if e = tx.QueryRow("SELECT deadline FROM scanner_dispatch WHERE job=?", j.ID).Scan(&deadline); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	stamp := q.now().UTC().Format(time.RFC3339Nano)
	if _, e = q.live(tx, l); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	created, e := time.Parse(time.RFC3339Nano, stamp)
	queued, qe := time.Parse(time.RFC3339Nano, j.Created)
	if e != nil || qe != nil || created.Before(queued) || !created.Before(time.Unix(deadline, 0)) {
		return scanevidence.LaunchRecord{}, ErrLease
	}
	if e = matchWorkspaceTx(tx, j, p, stamp); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	d := scanevidence.Launch{Schema: "1.0", Owner: j.Owner, Job: j.ID, Request: j.RequestDigest, App: j.Input.App, Repository: j.Input.Repository, Map: j.Input.MapDigest, Lock: j.LockDigest, Version: pin.Version, Image: pin.Image, Profile: "repo_offline-network-none-v1", Duration: j.Input.Duration, Plan: p, Created: stamp, Deadline: time.Unix(deadline, 0).UTC().Format(time.RFC3339)}
	b, e := json.Marshal(d)
	if e != nil || len(b) > maxLaunchBytes {
		return scanevidence.LaunchRecord{}, ErrInput
	}
	hash := domain.Hash(b)
	if _, e = tx.Exec("INSERT INTO scanner_launches VALUES(?,?,?,?,?,?,?,?,?)", j.ID, p.Tool, j.Owner, j.RequestDigest, p.Container, p.Workspace, hash, string(b), stamp); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	if e = store.AuditTx(tx, j.Owner, "scanner.launch", j.ID, "authorized", map[string]any{"tool_id": p.Tool, "launch_digest": hash, "request_digest": j.RequestDigest, "container_id": p.Container, "engine_digest": p.Engine, "workspace_id": p.Workspace, "registry_digest": p.Registry, "cleanup_confirmed": false}); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	return scanevidence.LaunchRecord{Digest: hash, Document: d}, nil
}

// Launches is owner-scoped, bounded and read-only. Records identify attempts;
// they do not prove a container started, stopped or was independently cleaned.
func (q *Queue) Launches(owner, id string) ([]scanevidence.LaunchRecord, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, owner))
	if e != nil {
		return nil, e
	}
	rows, e := tx.Query("SELECT tool FROM scanner_launches WHERE job=? ORDER BY tool", id)
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
	out := []scanevidence.LaunchRecord{}
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
		r, e := launchTx(tx, j, tool)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, nil
}

// matchLaunchTx checks a new receipt against its committed attempt. A preflight
// report with no container cannot erase uncertainty from a registered launch.
func matchLaunchTx(tx *sql.Tx, j Job, r scanevidence.Execution) error {
	l, e := launchTx(tx, j, r.Tool)
	if r.Container == "" {
		if e == sql.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		return ErrConflict
	}
	if e == sql.ErrNoRows {
		return ErrInput
	}
	if e != nil {
		return e
	}
	d := l.Document
	started, e := time.Parse(time.RFC3339Nano, r.Started)
	if e != nil {
		return ErrInput
	}
	stamp, e := time.Parse(time.RFC3339Nano, d.Created)
	if e != nil {
		return ErrConflict
	}
	// Execution.Started is captured during preflight, before registration.
	if started.After(stamp) || d.Plan.Container != r.Container || d.Plan.Snapshot != r.Snapshot.Digest || d.Version != r.Version || d.Image != r.Image || d.Profile != r.Profile || d.Lock != r.LockDigest || d.Duration != r.DurationLimit {
		return ErrInput
	}
	return nil
}
