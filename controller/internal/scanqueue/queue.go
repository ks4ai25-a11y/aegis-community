// SPDX-License-Identifier: Apache-2.0
// Package scanqueue persists owner-authorized offline scan requests. Execution
// belongs to a separate scanner worker; this package never accesses Docker.
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

var ErrConflict = errors.New("scan request conflicts with durable identity")
var ErrInput = errors.New("unsupported offline scan request")
var ErrFull = errors.New("scanner queue budget exhausted")
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{8,128}$`)
var toolIDs = map[string]bool{"semgrep_ce": true, "osv_v2": true, "trivy": true, "syft": true, "gitleaks": true, "bandit": true}

type Input struct {
	Schema     string   `json:"schema_version"`
	App        string   `json:"app_id"`
	Repository string   `json:"repository_id"`
	MapDigest  string   `json:"map_digest"`
	Mode       string   `json:"mode"`
	Tools      []string `json:"tool_ids"`
	Duration   int      `json:"tool_timeout_seconds"`
}
type Job struct {
	Schema          string `json:"schema_version"`
	ID              string `json:"job_id"`
	Owner           string `json:"owner_id"`
	Input           Input  `json:"input"`
	LockDigest      string `json:"tool_lock_digest"`
	RequestDigest   string `json:"request_digest"`
	State           string `json:"state"`
	CancelRequested bool   `json:"cancel_requested"`
	Created         string `json:"created_at"`
	Expires         string `json:"expires_at"`
	Finished        string `json:"finished_at,omitempty"`
	Error           string `json:"error_code,omitempty"`
}
type Queue struct {
	S *store.Store
	// LockDigest is provisioned by trusted startup, never a browser-selected pin.
	LockDigest string
	Pins       map[string]Pin
	Guards     scanevidence.GuardSet
	Now        func() time.Time
}

func (q *Queue) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

const columns = "id,owner,repository,app,map_digest,payload,lock_digest,request_digest,state,cancel_requested,created_at,expires,finished_at,error_code"

type scanner interface{ Scan(...any) error }

func read(row scanner) (Job, error) {
	j := Job{Schema: "1.0"}
	var payload, repo, app, mapDigest string
	var expires int64
	e := row.Scan(&j.ID, &j.Owner, &repo, &app, &mapDigest, &payload, &j.LockDigest, &j.RequestDigest, &j.State, &j.CancelRequested, &j.Created, &expires, &j.Finished, &j.Error)
	if e != nil {
		return j, e
	}
	if json.Unmarshal([]byte(payload), &j.Input) != nil || !valid(j.Input) || !digestPattern.MatchString(j.LockDigest) || requestDigest(j.Owner, j.Input, j.LockDigest) != j.RequestDigest || j.Input.Repository != repo || j.Input.App != app || j.Input.MapDigest != mapDigest {
		return Job{}, ErrConflict
	}
	j.Expires = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	return j, nil
}
func valid(in Input) bool {
	if in.Schema != "1.0" || in.App != "app_demo" || in.Repository == "" || len(in.Repository) > 128 || !digestPattern.MatchString(in.MapDigest) || in.Mode != "repo_offline" || in.Duration < 1 || in.Duration > 120 || len(in.Tools) < 1 || len(in.Tools) > 6 || !sort.StringsAreSorted(in.Tools) {
		return false
	}
	for i, id := range in.Tools {
		if !toolIDs[id] || (i > 0 && id == in.Tools[i-1]) {
			return false
		}
	}
	return true
}
func requestDigest(owner string, in Input, lock string) string {
	return domain.Digest(struct {
		Owner string `json:"owner_id"`
		Input Input  `json:"input"`
		Lock  string `json:"tool_lock_digest"`
	}{owner, in, lock})
}
func (q *Queue) Get(owner, id string) (Job, error) {
	return read(q.S.DB.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, owner))
}
func (q *Queue) List(owner string) ([]Job, error) {
	rows, e := q.S.DB.Query("SELECT "+columns+" FROM scanner_jobs WHERE owner=? ORDER BY created_at DESC,id DESC LIMIT 100", owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, e := read(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (q *Queue) Enqueue(owner, key string, in Input) (Job, error) {
	if !valid(in) || !keyPattern.MatchString(key) || !digestPattern.MatchString(q.LockDigest) {
		return Job{}, ErrInput
	}
	// Defensive copy: callers cannot change the bound tool list after submission.
	in.Tools = append([]string{}, in.Tools...)
	digest := requestDigest(owner, in, q.LockDigest)
	tx, e := q.S.DB.Begin()
	if e != nil {
		return Job{}, e
	}
	defer tx.Rollback()
	old, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE owner=? AND idempotency_key=?", owner, key))
	if e == nil {
		if old.RequestDigest != digest {
			return Job{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return Job{}, e
	}
	var mapDigest, app string
	if e = tx.QueryRow("SELECT map_digest,app FROM repositories WHERE id=? AND owner=?", in.Repository, owner).Scan(&mapDigest, &app); e != nil {
		return Job{}, e
	}
	if mapDigest != in.MapDigest || app != in.App {
		return Job{}, ErrConflict
	}
	var active, total int
	if e = tx.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN owner=? AND state IN ('queued','running') THEN 1 ELSE 0 END),0) FROM scanner_jobs", owner).Scan(&total, &active); e != nil {
		return Job{}, e
	}
	if total >= 1000 || active >= 20 {
		return Job{}, ErrFull
	}
	now := q.now().UTC()
	j := Job{Schema: "1.0", ID: domain.ID(), Owner: owner, Input: in, LockDigest: q.LockDigest, RequestDigest: digest, State: "queued", Created: now.Format(time.RFC3339Nano), Expires: now.Add(15 * time.Minute).Format(time.RFC3339)}
	payload, e := json.Marshal(in)
	if e != nil {
		return Job{}, e
	}
	_, e = tx.Exec("INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires) VALUES(?,?,?,?,?,?,?,?,?,'queued',?,?)", j.ID, owner, in.Repository, in.App, in.MapDigest, j.LockDigest, digest, key, string(payload), j.Created, now.Add(15*time.Minute).Unix())
	if e != nil {
		return Job{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.enqueue", j.ID, "queued", map[string]any{"repository_id": in.Repository, "map_digest": in.MapDigest, "tool_lock_digest": j.LockDigest, "request_digest": digest, "tool_ids": in.Tools, "mode": in.Mode}); e != nil {
		return Job{}, e
	}
	if e = tx.Commit(); e != nil {
		return Job{}, e
	}
	return j, nil
}
func (q *Queue) Cancel(owner, id string) error {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE owner=? AND id=?", owner, id))
	if e != nil {
		return e
	}
	if j.CancelRequested || j.State == "cancelled" {
		return nil
	}
	if j.State != "queued" && j.State != "running" {
		return ErrConflict
	}
	_, e = tx.Exec("UPDATE scanner_jobs SET cancel_requested=1,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,finished_at=CASE WHEN state='queued' THEN ? ELSE finished_at END,error_code='OWNER_CANCELLED' WHERE id=? AND owner=?", q.now().UTC().Format(time.RFC3339Nano), id, owner)
	if e != nil {
		return e
	}
	if e = store.AuditTx(tx, owner, "scanner.cancel", id, "requested", nil); e != nil {
		return e
	}
	return tx.Commit()
}
