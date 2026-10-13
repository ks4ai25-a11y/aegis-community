// SPDX-License-Identifier: Apache-2.0
package research

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scope"
	"aegis.local/controller/internal/store"
	"aegis.local/controller/internal/verify"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrConflict = errors.New("request conflicts with existing durable state")
var ErrScope = errors.New("scope is inactive, expired, revoked or belongs to another owner")
var ErrLease = errors.New("worker lease is no longer valid")
var ErrFull = errors.New("research queue is full")

type Queue struct {
	S   *store.Store
	Now func() time.Time
}

func (q *Queue) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

type GrantRecord struct {
	Grant             scope.Grant `json:"grant"`
	Digest            string      `json:"approved_digest"`
	State             string      `json:"state"`
	RequestsRemaining int         `json:"requests_remaining"`
}

func (q *Queue) CreateGrant(owner string, minutes int) (GrantRecord, error) {
	if minutes < 1 || minutes > 60 {
		return GrantRecord{}, fmt.Errorf("scope lifetime must be 1–60 minutes")
	}
	g := scope.Demo(owner, q.now().Add(time.Duration(minutes)*time.Minute))
	g.Created = q.now().UTC().Format(time.RFC3339Nano)
	if e := scope.Validate(g, owner, q.now()); e != nil {
		return GrantRecord{}, e
	}
	b, _ := json.Marshal(g)
	d := domain.Digest(g)
	expiry, _ := time.Parse(time.RFC3339Nano, g.Expires)
	tx, e := q.S.DB.Begin()
	if e != nil {
		return GrantRecord{}, e
	}
	defer tx.Rollback()
	_, e = tx.Exec("INSERT INTO scope_grants(id,owner,app,document,digest,state,expires,created_at) VALUES(?,?,?,?,?,'draft',?,?)", g.ID, owner, g.App, string(b), d, expiry.Unix(), g.Created)
	if e != nil {
		return GrantRecord{}, e
	}
	if e = store.AuditTx(tx, owner, "scope.draft", g.ID, "draft", map[string]string{"digest": d}); e != nil {
		return GrantRecord{}, e
	}
	if e = tx.Commit(); e != nil {
		return GrantRecord{}, e
	}
	return GrantRecord{Grant: g, Digest: d, State: "draft", RequestsRemaining: g.Requests}, nil
}
func (q *Queue) Grant(owner, id string) (GrantRecord, error) {
	var b string
	var r GrantRecord
	var used int
	e := q.S.DB.QueryRow("SELECT document,digest,state,requests_used FROM scope_grants WHERE id=? AND owner=?", id, owner).Scan(&b, &r.Digest, &r.State, &used)
	if e != nil {
		return r, e
	}
	e = json.Unmarshal([]byte(b), &r.Grant)
	r.RequestsRemaining = r.Grant.Requests - used
	if e == nil && domain.Digest(r.Grant) != r.Digest {
		e = fmt.Errorf("scope document integrity mismatch")
	}
	return r, e
}
func (q *Queue) Approve(owner, id, digest string, ack bool) (GrantRecord, error) {
	r, e := q.Grant(owner, id)
	if e != nil {
		return r, e
	}
	if ack && digest == r.Digest && r.State == "active" && scope.Validate(r.Grant, owner, q.now()) == nil {
		return r, nil
	}
	if !ack || digest != r.Digest || r.State != "draft" {
		return r, ErrConflict
	}
	if e = scope.Validate(r.Grant, owner, q.now()); e != nil {
		return r, ErrScope
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return r, e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE scope_grants SET state='active' WHERE id=? AND owner=? AND digest=? AND state='draft' AND expires>?", id, owner, digest, q.now().Unix())
	if e != nil {
		return r, e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return r, ErrConflict
	}
	if e = store.AuditTx(tx, owner, "scope.approve", id, "approved", map[string]string{"digest": digest}); e != nil {
		return r, e
	}
	if e = tx.Commit(); e != nil {
		return r, e
	}
	r.State = "active"
	return r, nil
}
func (q *Queue) Revoke(owner, id string) error {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE scope_grants SET state='revoked' WHERE id=? AND owner=?", id, owner)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	_, e = tx.Exec("UPDATE research_jobs SET state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,cancel_requested=1,error_code='SCOPE_REVOKED',finished_at=CASE WHEN state='queued' THEN ? ELSE finished_at END WHERE scope=? AND owner=? AND state IN ('queued','running')", domain.Now(), id, owner)
	if e != nil {
		return e
	}
	if e = store.AuditTx(tx, owner, "scope.revoke", id, "revoked", nil); e != nil {
		return e
	}
	return tx.Commit()
}

type Input struct {
	Schema       string `json:"schema_version"`
	App          string `json:"app_id"`
	Scope        string `json:"scope_grant_id"`
	ScopeDigest  string `json:"scope_digest"`
	Fixture      string `json:"fixture_id"`
	PolicyDigest string `json:"policy_digest"`
}
type Job struct {
	Schema      string `json:"schema_version"`
	ID          string `json:"job_id"`
	Owner       string `json:"owner_id"`
	App         string `json:"app_id"`
	Kind        string `json:"job_type"`
	Scope       string `json:"scope_grant_id"`
	InputDigest string `json:"input_digest"`
	State       string `json:"state"`
	Attempts    int    `json:"attempts"`
	Created     string `json:"created_at"`
	Finished    string `json:"finished_at,omitempty"`
	Error       string `json:"error_code,omitempty"`
	Report      string `json:"report_digest,omitempty"`
}
type Lease struct {
	Job    Job
	Token  string
	Input  Input
	Policy domain.Policy
	Grant  scope.Grant
}

const columns = "id,owner,app,kind,scope,input_digest,state,attempts,created_at,finished_at,error_code,report_digest"

type rowScanner interface{ Scan(...any) error }

func scanJob(row rowScanner) (Job, error) {
	j := Job{Schema: "1.0"}
	e := row.Scan(&j.ID, &j.Owner, &j.App, &j.Kind, &j.Scope, &j.InputDigest, &j.State, &j.Attempts, &j.Created, &j.Finished, &j.Error, &j.Report)
	return j, e
}
func (q *Queue) Get(owner, id string) (Job, error) {
	return scanJob(q.S.DB.QueryRow("SELECT "+columns+" FROM research_jobs WHERE id=? AND owner=?", id, owner))
}
func (q *Queue) List(owner string) ([]Job, error) {
	rows, e := q.S.DB.Query("SELECT "+columns+" FROM research_jobs WHERE owner=? ORDER BY created_at DESC,id DESC LIMIT 100", owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (q *Queue) Enqueue(owner, key string, in Input) (Job, error) {
	if len(key) < 8 || len(key) > 128 || in.Schema != "1.0" || in.App != "app_demo" || in.Fixture != scope.Fixture {
		return Job{}, fmt.Errorf("invalid typed job request")
	}
	requestDigest := domain.Digest(in)
	var oldID, oldDigest string
	e := q.S.DB.QueryRow("SELECT id,request_digest FROM research_jobs WHERE owner=? AND idempotency_key=?", owner, key).Scan(&oldID, &oldDigest)
	if e == nil {
		if oldDigest != requestDigest {
			return Job{}, ErrConflict
		}
		return q.Get(owner, oldID)
	}
	if e != sql.ErrNoRows {
		return Job{}, e
	}
	grant, e := q.Grant(owner, in.Scope)
	if e != nil || grant.State != "active" || grant.RequestsRemaining < 4 || grant.Digest != in.ScopeDigest || scope.Validate(grant.Grant, owner, q.now()) != nil {
		return Job{}, ErrScope
	}
	p, e := q.S.Policy(in.PolicyDigest)
	if e != nil || domain.Digest(p) != in.PolicyDigest {
		return Job{}, fmt.Errorf("unknown immutable policy")
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return Job{}, e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM research_jobs WHERE state IN ('queued','running')").Scan(&count); e != nil {
		return Job{}, e
	}
	if count >= 100 {
		return Job{}, ErrFull
	}
	// Recheck authority inside the durable enqueue transaction.
	var state, digest string
	var expires int64
	if e = tx.QueryRow("SELECT state,digest,expires FROM scope_grants WHERE id=? AND owner=?", in.Scope, owner).Scan(&state, &digest, &expires); e != nil || state != "active" || digest != in.ScopeDigest || expires <= q.now().Unix() {
		return Job{}, ErrScope
	}
	b, _ := json.Marshal(in)
	id := domain.ID()
	at := q.now().UTC().Format(time.RFC3339Nano)
	_, e = tx.Exec("INSERT INTO research_jobs(id,owner,app,kind,scope,input_digest,request_digest,idempotency_key,state,payload,created_at) VALUES(?,?,?,'waf_fixture',?,?,?,?,'queued',?,?)", id, owner, in.App, in.Scope, in.PolicyDigest, requestDigest, key, string(b), at)
	if e != nil {
		return Job{}, e
	}
	if e = store.AuditTx(tx, owner, "research.enqueue", id, "queued", map[string]string{"scope_digest": grant.Digest, "request_digest": requestDigest}); e != nil {
		return Job{}, e
	}
	if e = tx.Commit(); e != nil {
		return Job{}, e
	}
	return q.Get(owner, id)
}
func (q *Queue) Claim(worker string) (Lease, error) {
	if worker == "" || len(worker) > 128 {
		return Lease{}, fmt.Errorf("invalid worker identity")
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return Lease{}, e
	}
	defer tx.Rollback()
	now := q.now().Unix()
	at := q.now().UTC().Format(time.RFC3339Nano)
	// Reconcile interrupted/unauthorized jobs with the same audit transaction.
	rows, e := tx.Query("SELECT id,owner,state FROM research_jobs WHERE (state='running' AND lease_until<=?) OR (state='queued' AND (cancel_requested=1 OR scope NOT IN (SELECT id FROM scope_grants WHERE state='active' AND expires>? AND requests_used=0))) ORDER BY id LIMIT 201", now, now)
	if e != nil {
		return Lease{}, e
	}
	type recovered struct{ id, owner, state string }
	stale := []recovered{}
	for rows.Next() {
		var r recovered
		if e = rows.Scan(&r.id, &r.owner, &r.state); e != nil {
			rows.Close()
			return Lease{}, e
		}
		stale = append(stale, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return Lease{}, e
	}
	if len(stale) > 200 {
		return Lease{}, ErrFull
	}
	for _, r := range stale {
		state, code := "cancelled", "SCOPE_UNAVAILABLE"
		if r.state == "running" {
			state, code = "timeout", "WORKER_LEASE_EXPIRED"
		}
		if _, e = tx.Exec("UPDATE research_jobs SET state=?,error_code=?,finished_at=?,lease_token='',worker='',lease_until=0 WHERE id=? AND state=?", state, code, at, r.id, r.state); e != nil {
			return Lease{}, e
		}
		if e = store.AuditTx(tx, r.owner, "research.recovered", r.id, state, map[string]string{"error_code": code}); e != nil {
			return Lease{}, e
		}
	}
	var running int
	if e = tx.QueryRow("SELECT count(*) FROM research_jobs WHERE state='running'").Scan(&running); e != nil {
		return Lease{}, e
	}
	if running > 0 {
		if e = tx.Commit(); e != nil {
			return Lease{}, e
		}
		return Lease{}, sql.ErrNoRows
	}
	j, e := scanJob(tx.QueryRow("SELECT " + columns + " FROM research_jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1"))
	if e == sql.ErrNoRows {
		if e = tx.Commit(); e != nil {
			return Lease{}, e
		}
		return Lease{}, sql.ErrNoRows
	}
	if e != nil {
		return Lease{}, e
	}
	var payload, document, digest, requestDigest string
	if e = tx.QueryRow("SELECT payload,request_digest FROM research_jobs WHERE id=?", j.ID).Scan(&payload, &requestDigest); e != nil {
		return Lease{}, e
	}
	if e = tx.QueryRow("SELECT document,digest FROM scope_grants WHERE id=? AND owner=?", j.Scope, j.Owner).Scan(&document, &digest); e != nil {
		return Lease{}, e
	}
	var in Input
	var g scope.Grant
	if json.Unmarshal([]byte(payload), &in) != nil || json.Unmarshal([]byte(document), &g) != nil || domain.Digest(g) != digest || in.ScopeDigest != digest || scope.Validate(g, j.Owner, q.now()) != nil {
		return Lease{}, ErrScope
	}
	if domain.Digest(in) != requestDigest || in.Schema != "1.0" || in.App != j.App || in.Scope != j.Scope || in.Fixture != scope.Fixture || in.PolicyDigest != j.InputDigest {
		return Lease{}, fmt.Errorf("job input integrity mismatch")
	}
	var policyDocument string
	if e = tx.QueryRow("SELECT document FROM policies WHERE digest=?", in.PolicyDigest).Scan(&policyDocument); e != nil {
		return Lease{}, e
	}
	var p domain.Policy
	if json.Unmarshal([]byte(policyDocument), &p) != nil || domain.Digest(p) != j.InputDigest {
		return Lease{}, fmt.Errorf("job policy identity unavailable")
	}
	res, e := tx.Exec("UPDATE scope_grants SET requests_used=requests_used+4 WHERE id=? AND owner=? AND state='active' AND expires>? AND requests_used=0", g.ID, j.Owner, now)
	if e != nil {
		return Lease{}, e
	}
	reserved, _ := res.RowsAffected()
	if reserved != 1 {
		return Lease{}, ErrScope
	}
	token := domain.ID()
	res, e = tx.Exec("UPDATE research_jobs SET state='running',worker=?,lease_token=?,lease_until=?,attempts=attempts+1,started=? WHERE id=? AND state='queued'", worker, token, now+15, now, j.ID)
	if e != nil {
		return Lease{}, e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Lease{}, ErrLease
	}
	if e = store.AuditTx(tx, j.Owner, "research.claim", j.ID, "running", map[string]any{"worker_id": worker, "requests_reserved": 4, "scope_digest": digest}); e != nil {
		return Lease{}, e
	}
	if e = tx.Commit(); e != nil {
		return Lease{}, e
	}
	j.State = "running"
	j.Attempts++
	return Lease{j, token, in, p, g}, nil
}

// Guard renews only a live lease with live authority. Workers call it throughout execution.
func (q *Queue) Guard(l Lease) error {
	now := q.now().Unix()
	res, e := q.S.DB.Exec("UPDATE research_jobs SET lease_until=? WHERE id=? AND lease_token=? AND state='running' AND cancel_requested=0 AND lease_until>? AND started+30>? AND scope IN (SELECT id FROM scope_grants WHERE state='active' AND expires>? AND digest=?)", now+15, l.Job.ID, l.Token, now, now, now, l.Input.ScopeDigest)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrLease
	}
	return nil
}
func (q *Queue) Cancel(owner, id string) error {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE research_jobs SET cancel_requested=1,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,finished_at=CASE WHEN state='queued' THEN ? ELSE finished_at END,error_code='CANCEL_REQUESTED' WHERE id=? AND owner=? AND state IN ('queued','running')", q.now().UTC().Format(time.RFC3339Nano), id, owner)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if e = store.AuditTx(tx, owner, "research.cancel", id, "cancel_requested", nil); e != nil {
		return e
	}
	return tx.Commit()
}
func (q *Queue) Finish(l Lease, report *domain.Report, code string) error {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := q.now().Unix()
	var state, token string
	var cancelled int
	var until, started int64
	if e = tx.QueryRow("SELECT state,lease_token,cancel_requested,lease_until,started FROM research_jobs WHERE id=?", l.Job.ID).Scan(&state, &token, &cancelled, &until, &started); e != nil {
		return e
	}
	if state != "running" || token != l.Token {
		return ErrLease
	}
	var authority int
	e = tx.QueryRow("SELECT count(*) FROM scope_grants WHERE id=? AND owner=? AND state='active' AND expires>? AND digest=?", l.Job.Scope, l.Job.Owner, now, l.Input.ScopeDigest).Scan(&authority)
	if e != nil {
		return e
	}
	result := "failed"
	digest := ""
	if cancelled != 0 || authority != 1 {
		result = "cancelled"
		code = "SCOPE_OR_JOB_CANCELLED"
		report = nil
	} else if now >= until || now >= started+30 {
		result = "timeout"
		code = "JOB_DEADLINE_EXCEEDED"
		report = nil
	}
	if report != nil {
		if e = verify.ValidateReport(*report, l.Policy); e != nil {
			return e
		}
		r := *report
		r.Digest = ""
		if report.Digest != domain.Digest(r) || report.Candidate != l.Job.InputDigest || report.Fixture != l.Input.Fixture || report.ScopeGrant != l.Job.Scope || report.ScopeDigest != l.Input.ScopeDigest || report.Job != l.Job.ID {
			return fmt.Errorf("verifier report identity mismatch")
		}
		if report.Overall == "PASS" {
			result = "success"
			code = ""
		} else if report.Overall == "INCONCLUSIVE" {
			code = "VERIFICATION_INCONCLUSIVE"
		} else {
			code = "VERIFICATION_FAILED"
		}
		b, _ := json.Marshal(report)
		digest = report.Digest
		if _, e = tx.Exec("INSERT OR IGNORE INTO reports VALUES(?,?)", digest, string(b)); e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT OR IGNORE INTO report_owners VALUES(?,?)", digest, l.Job.Owner); e != nil {
			return e
		}
	}
	_, e = tx.Exec("UPDATE research_jobs SET state=?,report_digest=?,error_code=?,finished_at=?,lease_token='',worker='',lease_until=0 WHERE id=? AND lease_token=?", result, digest, code, q.now().UTC().Format(time.RFC3339Nano), l.Job.ID, l.Token)
	if e != nil {
		return e
	}
	if e = store.AuditTx(tx, l.Job.Owner, "research.finished", l.Job.ID, result, map[string]string{"report_digest": digest, "error_code": code}); e != nil {
		return e
	}
	return tx.Commit()
}
