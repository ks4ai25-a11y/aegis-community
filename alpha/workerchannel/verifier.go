// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"aegis.local/source/scanevidence"
	"context"
	"errors"
	"regexp"
	"time"
)

// VerifierClient deliberately does not expose worker Claim/Guard/Finish.
// Its responses identify controller metadata, never resource cleanup.
var verifierIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type VerifierClient struct {
	client               *Client
	id, engine, registry string
}

func NewVerifier(socket, credential, owner, id, engine, registry, lock string) (*VerifierClient, error) {
	if !verifierIDPattern.MatchString(id) || !hashPattern.MatchString(engine) || !hashPattern.MatchString(registry) || validateVerifierParent(credential) != nil {
		return nil, errors.New("invalid private verifier configuration")
	}
	c, e := New(socket, credential, owner, lock)
	if e != nil {
		return nil, e
	}
	return &VerifierClient{client: c, id: id, engine: engine, registry: registry}, nil
}
func (c *VerifierClient) Close() { c.client.Close() }
func (c *VerifierClient) configuration() error {
	if validateVerifierParent(c.client.credential) != nil || validateSocket(c.client.socket) != nil {
		return errors.New("private verifier channel identity unavailable")
	}
	return nil
}
func (c *VerifierClient) Identity(ctx context.Context) (scanevidence.VerifierIdentity, error) {
	if e := c.configuration(); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	var v scanevidence.VerifierIdentity
	if e := c.client.call(ctx, "verifier/identity", struct{}{}, &v, 8192); e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	if scanevidence.ValidateVerifierIdentity(v, c.client.owner, c.id, c.engine, c.registry, time.Now()) != nil {
		return scanevidence.VerifierIdentity{}, errors.New("verifier identity binding rejected")
	}
	return v, nil
}
func (c *VerifierClient) Context(ctx context.Context, job string) (scanevidence.CleanupContextRecord, error) {
	if !jobPattern.MatchString(job) {
		return scanevidence.CleanupContextRecord{}, errors.New("invalid verifier job identity")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	if _, e := c.Identity(bounded); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	if e := c.configuration(); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	var out scanevidence.CleanupContextRecord
	if e := c.client.call(bounded, "verifier/context", struct {
		Job string `json:"job_id"`
	}{job}, &out, 64<<10); e != nil {
		return scanevidence.CleanupContextRecord{}, e
	}
	observed, e := time.Parse(time.RFC3339Nano, out.Document.Observed)
	if e != nil || observed.Before(started.Add(-2*time.Second)) || observed.After(time.Now().Add(2*time.Second)) || scanevidence.ValidateCleanupContext(out, c.client.owner, c.id, job, c.engine, c.registry, c.client.lock) != nil {
		return scanevidence.CleanupContextRecord{}, errors.New("verifier context binding rejected")
	}
	return out, nil
}
