// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var ErrLease = errors.New("scanner lease or authority is no longer live")
var ErrCleanup = errors.New("scanner admission awaits confirmed workspace cleanup")
var workerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type Lease struct {
	Job    Job
	Worker string
	// A random capability is returned only to the trusted enrolled worker caller.
	// General JSON serialization, owner responses and audit never include it.
	Token    string `json:"-"`
	Map      source.Map
	Deadline time.Time
	Guards   scanevidence.GuardSet
}

// Claim is a controller-internal operation. Its caller must authenticate the
// isolated worker before calling; browser owner sessions do not grant this role.
func (q *Queue) Claim(worker, owner string) (Lease, error) {
	if !workerPattern.MatchString(worker) || owner == "" || len(owner) > 128 || !digestPattern.MatchString(q.LockDigest) || !q.Guards.Valid() {
		return Lease{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return Lease{}, e
	}
	defer tx.Rollback()
	now := q.now().Unix()
	if e = workerAuthority(tx, worker, owner, now); e != nil {
		return Lease{}, e
	}
	if e = q.reconcileTx(tx, now); e != nil {
		return Lease{}, e
	}
	var occupied int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&occupied); e != nil {
		return Lease{}, e
	}
	if occupied > 0 {
		if e = tx.Commit(); e != nil {
			return Lease{}, e
		}
		return Lease{}, ErrCleanup
	}
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE state='queued' AND cancel_requested=0 AND owner=? AND expires>? ORDER BY created_at,id LIMIT 1", owner, now))
	if e == sql.ErrNoRows {
		if e = tx.Commit(); e != nil {
			return Lease{}, e
		}
		return Lease{}, sql.ErrNoRows
	}
	if e != nil {
		return Lease{}, e
	}
	m, e := q.authority(tx, j)
	if e != nil {
		if !errors.Is(e, ErrConflict) {
			return Lease{}, e
		}
		if e = terminalTx(tx, j, "tool_error", "SCAN_IDENTITY_CHANGED", q.now()); e != nil {
			return Lease{}, e
		}
		if e = tx.Commit(); e != nil {
			return Lease{}, e
		}
		return Lease{}, ErrConflict
	}
	bytes := make([]byte, 32)
	if _, e = rand.Read(bytes); e != nil {
		return Lease{}, e
	}
	token := hex.EncodeToString(bytes)
	// Each selected tool has its requested guard budget plus cleanup allowance;
	// capture has a separate bounded allowance. Never extend queued authority.
	deadline := now + int64(len(j.Input.Tools)*(j.Input.Duration+5)+60)
	expiry, _ := time.Parse(time.RFC3339, j.Expires)
	if deadline > expiry.Unix() {
		deadline = expiry.Unix()
	}
	until := now + 15
	if until > deadline {
		until = deadline
	}
	if _, e = tx.Exec("INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state,launch_protocol,workspace_protocol,guard_set_digest) VALUES(1,?,?,?,?,?,'active',1,1,?)", j.ID, worker, domain.Hash([]byte(token)), until, deadline, q.Guards.Digest); e != nil {
		return Lease{}, e
	}
	if _, e = tx.Exec("UPDATE scanner_jobs SET state='running' WHERE id=? AND state='queued'", j.ID); e != nil {
		return Lease{}, e
	}
	if e = store.AuditTx(tx, j.Owner, "scanner.claim", j.ID, "running", map[string]any{"worker_id": worker, "request_digest": j.RequestDigest, "map_digest": j.Input.MapDigest, "tool_lock_digest": j.LockDigest, "deadline_unix": deadline, "launch_protocol": "1.0", "workspace_protocol": "1.0", "guard_set_digest": q.Guards.Digest}); e != nil {
		return Lease{}, e
	}
	if e = tx.Commit(); e != nil {
		return Lease{}, e
	}
	j.State = "running"
	return Lease{Job: j, Worker: worker, Token: token, Map: m, Deadline: time.Unix(deadline, 0).UTC(), Guards: q.Guards}, nil
}

// authority checks registered source identity, not current mounted source bytes.
// The worker must still use source.Capture with this exact map before execution.
func (q *Queue) authority(tx *sql.Tx, j Job) (source.Map, error) {
	var current, app, asset, document string
	e := tx.QueryRow("SELECT r.map_digest,r.app,r.asset,m.document FROM repositories r JOIN application_maps m ON m.repository=r.id AND m.digest=? WHERE r.id=? AND r.owner=?", j.Input.MapDigest, j.Input.Repository, j.Owner).Scan(&current, &app, &asset, &document)
	if e == sql.ErrNoRows {
		return source.Map{}, ErrConflict
	}
	if e != nil {
		return source.Map{}, e
	}
	var m source.Map
	if len(document) > 60000 || json.Unmarshal([]byte(document), &m) != nil {
		return m, ErrConflict
	}
	expected := m.Digest
	canonical := m
	canonical.Digest = ""
	canonical.Observed = ""
	if j.LockDigest != q.LockDigest || current != j.Input.MapDigest || app != j.Input.App || m.App != app || m.Schema != "1.0" || m.SourceRef != "mounted-asset:"+asset || expected != current || domain.Digest(canonical) != expected {
		return m, ErrConflict
	}
	return m, nil
}
func terminalTx(tx *sql.Tx, j Job, state, code string, now time.Time) error {
	if _, e := tx.Exec("UPDATE scanner_jobs SET state=?,error_code=?,finished_at=? WHERE id=?", state, code, now.UTC().Format(time.RFC3339Nano), j.ID); e != nil {
		return e
	}
	return store.AuditTx(tx, j.Owner, "scanner.finished", j.ID, state, map[string]string{"error_code": code})
}

// Reconcile closes expired jobs without retrying external execution. The global
// dispatch slot persists as cleanup_required until a separate verified cleanup.
func (q *Queue) Reconcile() error {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = q.reconcileTx(tx, q.now().Unix()); e != nil {
		return e
	}
	return tx.Commit()
}
func (q *Queue) reconcileTx(tx *sql.Tx, now int64) error {
	rows, e := tx.Query("SELECT "+columns+" FROM scanner_jobs WHERE state='queued' AND expires<=? ORDER BY created_at,id LIMIT 200", now)
	if e != nil {
		return e
	}
	stale := []Job{}
	for rows.Next() {
		j, e := read(rows)
		if e != nil {
			rows.Close()
			return e
		}
		stale = append(stale, j)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, j := range stale {
		if e = terminalTx(tx, j, "timeout", "QUEUE_EXPIRED", q.now()); e != nil {
			return e
		}
	}
	var id, state string
	var until, deadline int64
	e = tx.QueryRow("SELECT job,state,lease_until,deadline FROM scanner_dispatch WHERE slot=1").Scan(&id, &state, &until, &deadline)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	if state != "active" || (until > now && deadline > now) {
		return nil
	}
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=?", id))
	if e != nil {
		return e
	}
	if j.State != "running" {
		return ErrConflict
	}
	final, code := "timeout", "WORKER_LEASE_EXPIRED"
	if j.CancelRequested {
		final, code = "cancelled", "OWNER_CANCELLED"
		if j.Error == "WORKER_REVOKED" {
			code = "WORKER_REVOKED"
		}
	} else if deadline <= now {
		code = "JOB_DEADLINE_EXCEEDED"
	}
	if e = terminalTx(tx, j, final, code, q.now()); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE scanner_dispatch SET state='cleanup_required' WHERE slot=1"); e != nil {
		return e
	}
	return nil
}
func (q *Queue) live(tx *sql.Tx, l Lease) (Job, error) {
	if len(l.Token) != 64 || !workerPattern.MatchString(l.Worker) {
		return Job{}, ErrLease
	}
	var id, state, guardSet string
	var until, deadline int64
	var protocol, workspaceProtocol int
	e := tx.QueryRow("SELECT job,state,lease_until,deadline,launch_protocol,workspace_protocol,guard_set_digest FROM scanner_dispatch WHERE slot=1 AND worker=? AND token_hash=?", l.Worker, domain.Hash([]byte(l.Token))).Scan(&id, &state, &until, &deadline, &protocol, &workspaceProtocol, &guardSet)
	if e == sql.ErrNoRows {
		return Job{}, ErrLease
	}
	if e != nil {
		return Job{}, e
	}
	now := q.now().Unix()
	if id != l.Job.ID || state != "active" || until <= now || deadline <= now || protocol != 1 || workspaceProtocol != 1 || !q.Guards.Valid() || guardSet != q.Guards.Digest {
		return Job{}, ErrLease
	}
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=?", id))
	if e != nil {
		return Job{}, e
	}
	if e = workerAuthority(tx, l.Worker, j.Owner, now); e != nil {
		return Job{}, e
	}
	if j.State != "running" || j.CancelRequested || j.RequestDigest != l.Job.RequestDigest {
		return Job{}, ErrLease
	}
	if _, e = q.authority(tx, j); e != nil {
		if errors.Is(e, ErrConflict) {
			return Job{}, ErrLease
		}
		return Job{}, e
	}
	return j, nil
}

// Guard must run throughout capture, scanner execution and cleanup. Renewal
// never revives an expired capability or exceeds the immutable suite deadline.
func (q *Queue) Guard(l Lease) error {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = q.live(tx, l); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE scanner_dispatch SET lease_until=min(?,deadline) WHERE slot=1", q.now().Unix()+15); e != nil {
		return e
	}
	return tx.Commit()
}

// Fail records only finite sanitized error codes. It keeps admission closed;
// even a returned tool error does not itself confirm container/workspace absence.
func (q *Queue) Fail(l Lease, code string) error {
	switch code {
	case "SCANNER_EXECUTION_FAILED", "SOURCE_CAPTURE_FAILED", "TOOL_UNAVAILABLE":
	default:
		return ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// A retry of an already committed finite failure is idempotent, including
	// after its lease expires. It cannot change the terminal result or admission.
	var oldCode, oldDigest string
	e = tx.QueryRow("SELECT j.error_code,j.request_digest FROM scanner_jobs j JOIN scanner_dispatch d ON d.job=j.id WHERE j.id=? AND j.state='tool_error' AND d.state='cleanup_required' AND d.worker=? AND d.token_hash=?", l.Job.ID, l.Worker, domain.Hash([]byte(l.Token))).Scan(&oldCode, &oldDigest)
	if e == nil {
		if oldCode != code || oldDigest != l.Job.RequestDigest {
			return ErrConflict
		}
		return nil
	}
	if e != sql.ErrNoRows {
		return e
	}
	j, e := q.live(tx, l)
	if e != nil {
		return e
	}
	if e = terminalTx(tx, j, "tool_error", code, q.now()); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE scanner_dispatch SET state='cleanup_required' WHERE slot=1"); e != nil {
		return e
	}
	return tx.Commit()
}

// Enrollment is checked inside claim/renew transactions, closing the gap
// between transport authentication and a concurrent operator revocation.
func workerAuthority(tx *sql.Tx, worker, owner string, now int64) error {
	var n int
	e := tx.QueryRow("SELECT count(*) FROM scanner_workers w JOIN settings s ON s.key='repository_mount_owner' AND s.value=w.owner WHERE w.id=? AND w.owner=? AND w.state='active' AND w.expires>?", worker, owner, now).Scan(&n)
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrLease
	}
	return nil
}
