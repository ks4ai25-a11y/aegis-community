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

// ReconcilerClient exposes scoped metadata only in this protocol revision.
// It cannot claim a job, authorize/complete a mutation or release a dispatch.
type ReconcilerClient struct {
	client                                           *Client
	id, binding, engine, registry, policy, namespace string
}

func NewReconciler(socket, credential, owner, id, binding, engine, registry, policy, namespace, lock string) (*ReconcilerClient, error) {
	if !verifierIDPattern.MatchString(id) || !hashPattern.MatchString(binding) || !hashPattern.MatchString(engine) || !hashPattern.MatchString(registry) || !hashPattern.MatchString(policy) || !hashPattern.MatchString(namespace) || validateVerifierParent(credential) != nil {
		return nil, errors.New("invalid private reconciler configuration")
	}
	c, err := New(socket, credential, owner, lock)
	if err != nil {
		return nil, err
	}
	return &ReconcilerClient{client: c, id: id, binding: binding, engine: engine, registry: registry, policy: policy, namespace: namespace}, nil
}

func (c *ReconcilerClient) Close() { c.client.Close() }

func (c *ReconcilerClient) Identity(ctx context.Context) (scanevidence.ReconcilerIdentity, error) {
	if validateVerifierParent(c.client.credential) != nil || validateSocket(c.client.socket) != nil {
		return scanevidence.ReconcilerIdentity{}, errors.New("private reconciler channel identity unavailable")
	}
	var v scanevidence.ReconcilerIdentity
	if err := c.client.call(ctx, "reconciler/identity", struct{}{}, &v, 8192); err != nil {
		return v, err
	}
	if !v.Valid(time.Now()) || v.ID != c.id || v.Owner != c.client.owner || v.Binding != c.binding || v.Engine != c.engine || v.Registry != c.registry || v.Policy != c.policy || v.Namespace != c.namespace {
		return scanevidence.ReconcilerIdentity{}, errors.New("reconciler identity rejected")
	}
	return v, nil
}

func (c *ReconcilerClient) Snapshot(ctx context.Context, job, generation string) (scanevidence.ReconciliationSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	v, err := c.Identity(ctx)
	if err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return scanevidence.ReconciliationSnapshot{}, err
	}
	r := scanevidence.ReconciliationRequest{Job: job, Generation: generation, Challenge: hex.EncodeToString(nonce[:])}
	if !r.Valid() {
		return scanevidence.ReconciliationSnapshot{}, errors.New("invalid reconciliation request")
	}
	var s scanevidence.ReconciliationSnapshot
	if err = c.client.call(ctx, "reconciler/context", r, &s, 64<<10); err != nil {
		return s, err
	}
	observed, err := time.Parse(time.RFC3339Nano, s.Observed)
	if err != nil || observed.Before(started.Add(-2*time.Second)) || s.Membership.Lock != c.client.lock || !scanevidence.ValidateReconciliationSnapshot(s, v, r, time.Now()) {
		return scanevidence.ReconciliationSnapshot{}, errors.New("reconciliation membership rejected")
	}
	return s, nil
}
