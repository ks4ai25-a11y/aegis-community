// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"aegis.local/source/scanevidence"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// AuthorizerClient exposes no worker leases or cleanup release. No operation
// retries a native engine mutation. Admission replay is explicit and immutable.
type AuthorizerClient struct {
	client                                  *Client
	id, engine, registry, policy, namespace string
}

func NewAuthorizer(socket, credential, owner, id, engine, registry, policy, namespace, lock string) (*AuthorizerClient, error) {
	if !verifierIDPattern.MatchString(id) || !hashPattern.MatchString(engine) || !hashPattern.MatchString(registry) || !hashPattern.MatchString(policy) || !hashPattern.MatchString(namespace) || validateVerifierParent(credential) != nil {
		return nil, errors.New("invalid private authorizer configuration")
	}
	c, e := New(socket, credential, owner, lock)
	if e != nil {
		return nil, e
	}
	return &AuthorizerClient{client: c, id: id, engine: engine, registry: registry, policy: policy, namespace: namespace}, nil
}
func (c *AuthorizerClient) Close() { c.client.Close() }
func (c *AuthorizerClient) configuration() error {
	if validateVerifierParent(c.client.credential) != nil || validateSocket(c.client.socket) != nil {
		return errors.New("private authorizer channel identity unavailable")
	}
	return nil
}
func (c *AuthorizerClient) Identity(ctx context.Context) (scanevidence.AuthorizerIdentity, error) {
	if e := c.configuration(); e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	var v scanevidence.AuthorizerIdentity
	if e := c.client.call(ctx, "authorizer/identity", struct{}{}, &v, 8192); e != nil {
		return v, e
	}
	if scanevidence.ValidateAuthorizerIdentity(v, c.client.owner, c.id, c.engine, c.registry, c.policy, time.Now()) != nil {
		return scanevidence.AuthorizerIdentity{}, errors.New("authorizer identity rejected")
	}
	return v, nil
}
func (c *AuthorizerClient) Binding(ctx context.Context) (scanevidence.MutationBindingRecord, error) {
	if _, e := c.Identity(ctx); e != nil {
		return scanevidence.MutationBindingRecord{}, e
	}
	var b scanevidence.MutationBindingRecord
	if e := c.client.call(ctx, "authorizer/binding", struct{}{}, &b, 8192); e != nil {
		return b, e
	}
	if !b.Valid(c.client.owner, c.id, c.engine, c.registry, c.policy, c.namespace) {
		return scanevidence.MutationBindingRecord{}, errors.New("authorizer selected binding rejected")
	}
	return b, nil
}
func (c *AuthorizerClient) Launch(ctx context.Context, name, operation string) (scanevidence.AuthorizerLaunch, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	v, e := c.Identity(bounded)
	if e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return scanevidence.AuthorizerLaunch{}, e
	}
	r := scanevidence.AuthorizerLaunchRequest{Container: name, Operation: operation, Challenge: hex.EncodeToString(nonce)}
	if !r.Valid() {
		return scanevidence.AuthorizerLaunch{}, errors.New("invalid authorizer launch request")
	}
	var d scanevidence.AuthorizerLaunch
	if e = c.client.call(bounded, "authorizer/launch", r, &d, 32<<10); e != nil {
		return d, e
	}
	observed, e := time.Parse(time.RFC3339Nano, d.Observed)
	if e != nil || observed.Before(started.Add(-2*time.Second)) || !d.Valid(v, c.namespace, c.client.lock, r, time.Now()) {
		return scanevidence.AuthorizerLaunch{}, errors.New("authorizer launch scope rejected")
	}
	return d, nil
}
func (c *AuthorizerClient) Admit(ctx context.Context, d scanevidence.AuthorizerLaunch, descriptor, engineID string) (scanevidence.MutationAdmission, error) {
	if e := c.configuration(); e != nil {
		return scanevidence.MutationAdmission{}, e
	}
	r := scanevidence.MutationRequest{Generation: d.Generation.ID, Job: d.Generation.Job, Tool: d.Launch.Document.Plan.Tool, Operation: d.Operation, Launch: d.Launch.Digest, Descriptor: descriptor, EngineID: engineID}
	if !r.Valid() || !d.Binding.Valid(c.client.owner, c.id, c.engine, c.registry, c.policy, c.namespace) {
		return scanevidence.MutationAdmission{}, errors.New("invalid mutation admission request")
	}
	var a scanevidence.MutationAdmission
	if e := c.client.call(ctx, "authorizer/admit", r, &a, 8192); e != nil {
		return a, e
	}
	if !a.Intent.Valid() || a.Intent.Request != r || a.Intent.Workspace != d.Workspace.Digest || a.Intent.Container != d.Launch.Document.Plan.Container || (!a.Replay && a.Intent.State != "pending") {
		return scanevidence.MutationAdmission{}, errors.New("mutation admission identity rejected")
	}
	return a, nil
}
func (c *AuthorizerClient) Complete(ctx context.Context, in scanevidence.MutationCompletion) (scanevidence.MutationIntent, error) {
	if !in.Valid() {
		return scanevidence.MutationIntent{}, errors.New("invalid native completion")
	}
	if e := c.configuration(); e != nil {
		return scanevidence.MutationIntent{}, e
	}
	var out scanevidence.MutationIntent
	if e := c.client.call(ctx, "authorizer/complete", in, &out, 8192); e != nil {
		return out, e
	}
	if !out.Valid() || out.ID != in.Intent || out.Request.Generation != in.Generation || out.State != "completed" || out.Status != in.Status || out.EngineID != in.EngineID || out.Response != in.Response {
		return scanevidence.MutationIntent{}, errors.New("mutation completion identity rejected")
	}
	return out, nil
}
