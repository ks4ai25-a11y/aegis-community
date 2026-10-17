// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/store"
	"aegis.local/source/scanevidence"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"regexp"
	"time"
)

var nativeContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MutationBinding is selected only by a trusted local operator. Namespace is
// the protocol-2 filesystem identity, not the legacy registry path digest.
type MutationBinding struct {
	Owner      string `json:"owner_id"`
	Authorizer string `json:"authorizer_id"`
	Engine     string `json:"engine_digest"`
	Registry   string `json:"registry_digest"`
	Policy     string `json:"policy_digest"`
	Namespace  string `json:"registry_namespace_digest"`
	Broker     string `json:"broker_binding_digest"`
	Created    string `json:"created_at"`
	Digest     string `json:"-"`
}

func mutationBindingTx(tx *sql.Tx, owner string) (MutationBinding, error) {
	var b MutationBinding
	e := tx.QueryRow("SELECT digest,owner,authorizer,engine_digest,registry_digest,policy_digest,namespace_digest,broker_binding_digest,created_at FROM scanner_mutation_bindings WHERE owner=? AND state='active'", owner).Scan(&b.Digest, &b.Owner, &b.Authorizer, &b.Engine, &b.Registry, &b.Policy, &b.Namespace, &b.Broker, &b.Created)
	if e != nil {
		return b, e
	}
	if b.Owner != owner || !workerPattern.MatchString(b.Authorizer) || !digestPattern.MatchString(b.Engine) || !digestPattern.MatchString(b.Registry) || !digestPattern.MatchString(b.Policy) || !digestPattern.MatchString(b.Namespace) || !digestPattern.MatchString(b.Broker) || domain.Digest(b) != b.Digest {
		return MutationBinding{}, ErrConflict
	}
	if _, e = time.Parse(time.RFC3339Nano, b.Created); e != nil {
		return MutationBinding{}, ErrConflict
	}
	return b, nil
}

func authorizerTx(tx *sql.Tx, owner, id string, now time.Time) (scanevidence.AuthorizerIdentity, error) {
	v := scanevidence.AuthorizerIdentity{Schema: "1.0", Role: scanevidence.ScannerAuthorizerRole, Owner: owner, ID: id}
	var expiry int64
	e := tx.QueryRow("SELECT state,engine_digest,registry_digest,policy_digest,created_at,expires FROM scanner_authorizers WHERE owner=? AND id=?", owner, id).Scan(&v.State, &v.Engine, &v.Registry, &v.Policy, &v.Created, &expiry)
	if e != nil {
		return v, e
	}
	v.Expires = time.Unix(expiry, 0).UTC().Format(time.RFC3339)
	return v, scannerauth.AuthorizeAuthorizerTx(tx, v, now.Unix())
}

// BindMutationAuthorizer cannot adopt an existing dispatch or replace a live
// selection. It does not enable daemon mediation or cleanup release by itself.
func (q *Queue) BindMutationAuthorizer(owner, id, namespace string) (MutationBinding, error) {
	if owner == "" || len(owner) > 128 || !workerPattern.MatchString(id) || !digestPattern.MatchString(namespace) {
		return MutationBinding{}, ErrInput
	}
	tx, e := q.S.DB.Begin()
	if e != nil {
		return MutationBinding{}, e
	}
	defer tx.Rollback()
	v, e := authorizerTx(tx, owner, id, q.now())
	if e != nil {
		return MutationBinding{}, e
	}
	base, e := q.engineBindingTx(tx, owner)
	if e != nil {
		return MutationBinding{}, e
	}
	broker, e := q.brokerBindingTx(tx, owner)
	if e != nil {
		return MutationBinding{}, e
	}
	if base.Document.Engine != v.Engine || base.Document.Registry != v.Registry {
		return MutationBinding{}, ErrConflict
	}
	old, e := mutationBindingTx(tx, owner)
	if e == nil {
		if old.Authorizer != id || old.Namespace != namespace || old.Engine != v.Engine || old.Registry != v.Registry || old.Policy != v.Policy || old.Broker != broker.Digest {
			return MutationBinding{}, ErrConflict
		}
		return old, nil
	}
	if e != sql.ErrNoRows {
		return MutationBinding{}, e
	}
	var n int
	if e = tx.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n); e != nil {
		return MutationBinding{}, e
	}
	if n != 0 {
		return MutationBinding{}, ErrCleanup
	}
	if e = tx.QueryRow("SELECT count(*) FROM scanner_mutation_bindings").Scan(&n); e != nil {
		return MutationBinding{}, e
	}
	if n >= 100 {
		return MutationBinding{}, ErrFull
	}
	b := MutationBinding{Owner: owner, Authorizer: id, Engine: v.Engine, Registry: v.Registry, Policy: v.Policy, Namespace: namespace, Broker: broker.Digest, Created: q.now().UTC().Format(time.RFC3339Nano)}
	b.Digest = domain.Digest(b)
	_, e = tx.Exec("INSERT INTO scanner_mutation_bindings(digest,owner,authorizer,engine_digest,registry_digest,policy_digest,namespace_digest,broker_binding_digest,created_at,state) VALUES(?,?,?,?,?,?,?,?,?,'active')", b.Digest, b.Owner, b.Authorizer, b.Engine, b.Registry, b.Policy, b.Namespace, b.Broker, b.Created)
	if e != nil {
		return MutationBinding{}, e
	}
	if e = store.AuditTx(tx, owner, "scanner.mutation_bind", b.Digest, "bound", map[string]any{"cleanup_release_authorized": false}); e != nil {
		return MutationBinding{}, e
	}
	if e = tx.Commit(); e != nil {
		return MutationBinding{}, e
	}
	return b, nil
}

// createGenerationTx runs in Claim's transaction. Legacy claims remain held
// permanently; only a selected authorizer creates a new ledger generation.
func (q *Queue) createGenerationTx(tx *sql.Tx, j Job, worker, leaseHash string, deadline int64) error {
	b, e := mutationBindingTx(tx, j.Owner)
	if e == sql.ErrNoRows {
		var retained int
		if e = tx.QueryRow("SELECT count(*) FROM scanner_mutation_bindings WHERE owner=?", j.Owner).Scan(&retained); e != nil {
			return e
		}
		if retained != 0 {
			return ErrLease
		}
		return nil
	}
	if e != nil {
		return e
	}
	v, e := authorizerTx(tx, j.Owner, b.Authorizer, q.now())
	if e != nil {
		return e
	}
	broker, e := q.brokerBindingTx(tx, j.Owner)
	if e != nil {
		return e
	}
	if b.Engine != v.Engine || b.Registry != v.Registry || b.Policy != v.Policy || b.Broker != broker.Digest || broker.Document.Worker != worker {
		return ErrLease
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO scanner_allocation_generations(job,id,owner,worker,binding_digest,lease_hash,deadline,guard_digest,created_at,state) VALUES(?,?,?,?,?,?,?,?,?,'open')", j.ID, hex.EncodeToString(nonce), j.Owner, worker, b.Digest, leaseHash, deadline, q.Guards.Digest, q.now().UTC().Format(time.RFC3339Nano))
	return e
}

type AllocationGeneration struct {
	ID       string `json:"generation_id"`
	Job      string `json:"job_id"`
	Binding  string `json:"binding_digest"`
	State    string `json:"state"`
	Deadline int64  `json:"deadline_unix"`
}

func (q *Queue) generationTx(tx *sql.Tx, v scanevidence.AuthorizerIdentity, job string, cleanup bool) (AllocationGeneration, MutationBinding, Job, error) {
	var g AllocationGeneration
	if e := scannerauth.AuthorizeAuthorizerTx(tx, v, q.now().Unix()); e != nil {
		return g, MutationBinding{}, Job{}, e
	}
	b, e := mutationBindingTx(tx, v.Owner)
	if e != nil {
		return g, b, Job{}, e
	}
	if b.Authorizer != v.ID || b.Engine != v.Engine || b.Registry != v.Registry || b.Policy != v.Policy {
		return g, b, Job{}, ErrLease
	}
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", job, v.Owner))
	if e != nil {
		return g, b, j, e
	}
	var worker, leaseHash, guard string
	e = tx.QueryRow("SELECT id,job,binding_digest,state,deadline,worker,lease_hash,guard_digest FROM scanner_allocation_generations WHERE job=? AND owner=?", job, v.Owner).Scan(&g.ID, &g.Job, &g.Binding, &g.State, &g.Deadline, &worker, &leaseHash, &guard)
	if e != nil {
		return g, b, j, e
	}
	var dispatchWorker, dispatchHash, dispatchState, dispatchGuard string
	var until, deadline int64
	e = tx.QueryRow("SELECT worker,token_hash,state,lease_until,deadline,guard_set_digest FROM scanner_dispatch WHERE job=?", job).Scan(&dispatchWorker, &dispatchHash, &dispatchState, &until, &deadline, &dispatchGuard)
	if e != nil {
		return g, b, j, e
	}
	if g.Binding != b.Digest || g.State == "released" || worker != dispatchWorker || leaseHash != dispatchHash || g.Deadline != deadline || guard != dispatchGuard || !q.Guards.Valid() || guard != q.Guards.Digest {
		return g, b, j, ErrLease
	}
	broker, e := q.brokerBindingTx(tx, v.Owner)
	if e != nil {
		return g, b, j, e
	}
	if broker.Digest != b.Broker || broker.Document.Worker != worker {
		return g, b, j, ErrLease
	}
	if !cleanup {
		if g.State != "open" || dispatchState != "active" || until <= q.now().Unix() || deadline <= q.now().Unix() || j.State != "running" || j.CancelRequested {
			return g, b, j, ErrLease
		}
		if e = workerAuthority(tx, worker, v.Owner, q.now().Unix()); e != nil {
			return g, b, j, e
		}
		if _, e = q.authority(tx, j); e != nil {
			return g, b, j, e
		}
	}
	return g, b, j, nil
}

// GenerationForAuthorizer returns private metadata only, never permission to
// mutate. A subsequent admission rechecks every condition transactionally.
func (q *Queue) GenerationForAuthorizer(ctx context.Context, v scanevidence.AuthorizerIdentity, job string) (AllocationGeneration, error) {
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return AllocationGeneration{}, e
	}
	defer tx.Rollback()
	g, _, _, e := q.generationTx(tx, v, job, false)
	return g, e
}

type MutationRequest struct {
	Generation string `json:"generation_id"`
	Job        string `json:"job_id"`
	Tool       string `json:"tool_id"`
	Operation  string `json:"operation"`
	Launch     string `json:"launch_digest"`
	Descriptor string `json:"descriptor_digest"`
	EngineID   string `json:"target_engine_id"`
}
type MutationIntent struct {
	ID        string          `json:"intent_id"`
	Request   MutationRequest `json:"request"`
	Workspace string          `json:"workspace_digest"`
	Container string          `json:"container"`
	State     string          `json:"state"`
	Response  string          `json:"response_digest,omitempty"`
	Status    int             `json:"response_status,omitempty"`
	EngineID  string          `json:"result_engine_id,omitempty"`
}
type MutationAdmission struct {
	Intent MutationIntent `json:"intent"`
	Replay bool           `json:"replay"`
}

const intentColumns = "id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,state,response_digest,response_status,result_engine_id"

func readIntent(row scanner) (MutationIntent, error) {
	var m MutationIntent
	e := row.Scan(&m.ID, &m.Request.Generation, &m.Request.Job, &m.Request.Tool, &m.Request.Operation, &m.Request.Launch, &m.Workspace, &m.Container, &m.Request.Descriptor, &m.Request.EngineID, &m.State, &m.Response, &m.Status, &m.EngineID)
	if e != nil {
		return m, e
	}
	r := m.Request
	expected := domain.Digest(struct {
		Domain               string
		Request              MutationRequest
		Workspace, Container string
	}{"aegis-scanner-mutation-intent-v1", r, m.Workspace, m.Container})
	if m.ID != expected || !nativeContainerID.MatchString(r.Generation) || !toolIDs[r.Tool] || !digestPattern.MatchString(r.Launch) || !digestPattern.MatchString(r.Descriptor) || !digestPattern.MatchString(m.Workspace) || !containerID.MatchString(m.Container) || (r.Operation != "create" && r.Operation != "start" && r.Operation != "remove") || (r.Operation == "create" && r.EngineID != "") || (r.Operation != "create" && !nativeContainerID.MatchString(r.EngineID)) {
		return MutationIntent{}, ErrConflict
	}
	if m.State == "pending" {
		if m.Response != "" || m.Status != 0 || m.EngineID != "" {
			return MutationIntent{}, ErrConflict
		}
	} else if m.State == "completed" {
		if !digestPattern.MatchString(m.Response) || !nativeContainerID.MatchString(m.EngineID) || (r.Operation == "create" && m.Status != 201) || (r.Operation != "create" && (m.Status != 204 || m.EngineID != r.EngineID)) {
			return MutationIntent{}, ErrConflict
		}
	} else {
		return MutationIntent{}, ErrConflict
	}
	return m, nil
}

// AdmitMutation commits a durable obligation before the native daemon plugin
// may reply positively. Replay must never be interpreted as a second engine
// invocation. The plugin must enforce its own durable one-shot request journal.
func (q *Queue) AdmitMutation(ctx context.Context, v scanevidence.AuthorizerIdentity, r MutationRequest) (MutationAdmission, error) {
	if !nativeContainerID.MatchString(r.Generation) || !toolIDs[r.Tool] || !digestPattern.MatchString(r.Launch) || !digestPattern.MatchString(r.Descriptor) || (r.Operation != "create" && r.Operation != "start" && r.Operation != "remove") || (r.Operation == "create" && r.EngineID != "") || (r.Operation != "create" && !nativeContainerID.MatchString(r.EngineID)) {
		return MutationAdmission{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return MutationAdmission{}, e
	}
	defer tx.Rollback()
	g, b, j, e := q.generationTx(tx, v, r.Job, r.Operation == "remove")
	if e != nil {
		return MutationAdmission{}, e
	}
	if g.ID != r.Generation {
		return MutationAdmission{}, ErrLease
	}
	launch, e := launchTx(tx, j, r.Tool)
	if e != nil {
		return MutationAdmission{}, e
	}
	workspace, e := workspaceTx(tx, j, r.Tool)
	if e != nil {
		return MutationAdmission{}, e
	}
	p := launch.Document.Plan
	if launch.Digest != r.Launch || launch.Document.Schema != "1.2" || !scanevidence.GuardedLaunchRevision(launch.Document) || p.Engine != b.Engine || p.Registry != b.Registry || workspace.Document.Plan.Registry != b.Registry || launch.Document.GuardSet != q.Guards.Digest {
		return MutationAdmission{}, ErrConflict
	}
	if e = matchWorkspaceTx(tx, j, p, launch.Document.Created); e != nil {
		return MutationAdmission{}, e
	}
	prior, e := readIntent(tx.QueryRow("SELECT "+intentColumns+" FROM scanner_mutation_intents WHERE generation=? AND tool=? AND operation=?", g.ID, r.Tool, r.Operation))
	if e == nil {
		if prior.Request != r || prior.Workspace != workspace.Digest || prior.Container != p.Container {
			return MutationAdmission{}, ErrConflict
		}
		return MutationAdmission{Intent: prior, Replay: true}, nil
	}
	if e != sql.ErrNoRows {
		return MutationAdmission{}, e
	}
	if r.Operation != "create" {
		created, e := readIntent(tx.QueryRow("SELECT "+intentColumns+" FROM scanner_mutation_intents WHERE generation=? AND tool=? AND operation='create'", g.ID, r.Tool))
		if e != nil {
			return MutationAdmission{}, e
		}
		if created.State != "completed" || created.EngineID != r.EngineID || created.Request.Launch != r.Launch {
			return MutationAdmission{}, ErrConflict
		}
		var pending, removed int
		if e = tx.QueryRow("SELECT count(*) FROM scanner_mutation_intents WHERE generation=? AND state='pending'", g.ID).Scan(&pending); e != nil {
			return MutationAdmission{}, e
		}
		if e = tx.QueryRow("SELECT count(*) FROM scanner_mutation_intents WHERE generation=? AND tool=? AND operation='remove'", g.ID, r.Tool).Scan(&removed); e != nil {
			return MutationAdmission{}, e
		}
		if pending != 0 || removed != 0 {
			return MutationAdmission{}, ErrConflict
		}
	}
	m := MutationIntent{Request: r, Workspace: workspace.Digest, Container: p.Container, State: "pending"}
	m.ID = domain.Digest(struct {
		Domain               string
		Request              MutationRequest
		Workspace, Container string
	}{"aegis-scanner-mutation-intent-v1", r, m.Workspace, m.Container})
	_, e = tx.Exec("INSERT INTO scanner_mutation_intents(id,generation,job,tool,operation,launch_digest,workspace_digest,container,descriptor_digest,target_engine_id,created_at,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending')", m.ID, g.ID, j.ID, r.Tool, r.Operation, r.Launch, m.Workspace, m.Container, r.Descriptor, r.EngineID, q.now().UTC().Format(time.RFC3339Nano))
	if e != nil {
		return MutationAdmission{}, e
	}
	if e = store.AuditTx(tx, v.Owner, "scanner.mutation_admit", m.ID, "pending", map[string]any{"operation": r.Operation, "cleanup_release_authorized": false}); e != nil {
		return MutationAdmission{}, e
	}
	if e = ctx.Err(); e != nil {
		return MutationAdmission{}, e
	}
	if e = tx.Commit(); e != nil {
		return MutationAdmission{}, e
	}
	return MutationAdmission{Intent: m}, nil
}

type MutationCompletion struct {
	Intent     string `json:"intent_id"`
	Generation string `json:"generation_id"`
	Status     int    `json:"response_status"`
	EngineID   string `json:"engine_id"`
	Response   string `json:"response_digest"`
}

// CompleteMutation records a successful native response, not independent
// absence. Missing/error responses stay pending even after cancellation/expiry.
// Only the original, still-enrolled authorizer may acknowledge completion.
func (q *Queue) CompleteMutation(ctx context.Context, v scanevidence.AuthorizerIdentity, c MutationCompletion) (MutationIntent, error) {
	if !digestPattern.MatchString(c.Intent) || !nativeContainerID.MatchString(c.Generation) || !nativeContainerID.MatchString(c.EngineID) || !digestPattern.MatchString(c.Response) {
		return MutationIntent{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return MutationIntent{}, e
	}
	defer tx.Rollback()
	m, e := readIntent(tx.QueryRow("SELECT "+intentColumns+" FROM scanner_mutation_intents WHERE id=? AND generation=?", c.Intent, c.Generation))
	if e != nil {
		return m, e
	}
	g, _, _, e := q.generationTx(tx, v, m.Request.Job, true)
	if e != nil {
		return MutationIntent{}, e
	}
	if g.ID != c.Generation {
		return MutationIntent{}, ErrLease
	}
	if (m.Request.Operation == "create" && c.Status != 201) || (m.Request.Operation != "create" && (c.Status != 204 || c.EngineID != m.Request.EngineID)) {
		return MutationIntent{}, ErrConflict
	}
	if m.State == "completed" {
		if m.Status != c.Status || m.EngineID != c.EngineID || m.Response != c.Response {
			return MutationIntent{}, ErrConflict
		}
		return m, nil
	}
	if m.State != "pending" {
		return MutationIntent{}, ErrConflict
	}
	if m.Request.Operation == "create" {
		var n int
		if e = tx.QueryRow("SELECT count(*) FROM scanner_mutation_intents WHERE operation='create' AND state='completed' AND result_engine_id=?", c.EngineID).Scan(&n); e != nil {
			return MutationIntent{}, e
		}
		if n != 0 {
			return MutationIntent{}, ErrConflict
		}
	}
	_, e = tx.Exec("UPDATE scanner_mutation_intents SET state='completed',response_digest=?,response_status=?,result_engine_id=?,completed_at=? WHERE id=? AND state='pending'", c.Response, c.Status, c.EngineID, q.now().UTC().Format(time.RFC3339Nano), c.Intent)
	if e != nil {
		return MutationIntent{}, e
	}
	if e = store.AuditTx(tx, v.Owner, "scanner.mutation_complete", m.ID, "completed", map[string]any{"operation": m.Request.Operation, "cleanup_release_authorized": false}); e != nil {
		return MutationIntent{}, e
	}
	if e = ctx.Err(); e != nil {
		return MutationIntent{}, e
	}
	if e = tx.Commit(); e != nil {
		return MutationIntent{}, e
	}
	m.State = "completed"
	m.Status = c.Status
	m.EngineID = c.EngineID
	m.Response = c.Response
	return m, nil
}
