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

// Confirm asks the controller to release a held dispatch after the caller
// observed every required allocation absent under the bound registry barrier.
// The controller recomputes membership; this only reports what was observed.
func (c *ReconcilerClient) Confirm(ctx context.Context, s scanevidence.ReconciliationSnapshot, absent []scanevidence.CleanupAbsence) (scanevidence.CleanupConfirmation, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := c.Identity(ctx)
	if err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	if absent == nil {
		absent = []scanevidence.CleanupAbsence{}
	}
	r := scanevidence.CleanupConfirmationRequest{Job: s.Membership.Job, Generation: s.Membership.Generation.ID, Membership: s.MembershipHash, Engine: c.engine, Namespace: c.namespace, Absent: absent}
	if !r.Valid() {
		return scanevidence.CleanupConfirmation{}, errors.New("invalid cleanup confirmation request")
	}
	var out scanevidence.CleanupConfirmation
	if err = c.client.call(ctx, "reconciler/confirm", r, &out, 16<<10); err != nil {
		return scanevidence.CleanupConfirmation{}, err
	}
	confirmed, err := time.Parse(time.RFC3339Nano, out.Confirmed)
	if err != nil || out.Schema != "1.0" || out.Reconciler != v.ID || !out.Released || out.Digest != scanevidence.NewCleanupConfirmation(v.ID, r, confirmed).Digest || !sameConfirmationRequest(out.Request, r) {
		return scanevidence.CleanupConfirmation{}, errors.New("cleanup confirmation rejected")
	}
	return out, nil
}

func sameConfirmationRequest(a, b scanevidence.CleanupConfirmationRequest) bool {
	if a.Job != b.Job || a.Generation != b.Generation || a.Membership != b.Membership || a.Engine != b.Engine || a.Namespace != b.Namespace || len(a.Absent) != len(b.Absent) {
		return false
	}
	for i := range a.Absent {
		if a.Absent[i] != b.Absent[i] {
			return false
		}
	}
	return true
}
