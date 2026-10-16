// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"aegis.local/source/scanevidence"
	"context"
	"errors"
	"time"
)

func (c *Client) EngineBinding(ctx context.Context) (scanevidence.EngineBindingRecord, error) {
	var out scanevidence.EngineBindingRecord
	if e := c.call(ctx, "engine-binding", struct{}{}, &out, 2048); e != nil {
		return scanevidence.EngineBindingRecord{}, e
	}
	created, e := time.Parse(time.RFC3339Nano, out.Document.Created)
	if !out.Valid(c.owner) || e != nil || created.After(time.Now()) {
		return scanevidence.EngineBindingRecord{}, errors.New("operator engine binding rejected")
	}
	return out, nil
}

func (c *Client) JournalBinding(ctx context.Context, base scanevidence.EngineBindingRecord) (scanevidence.JournalBindingRecord, error) {
	var out scanevidence.JournalBindingRecord
	if e := c.call(ctx, "engine-journal-binding", struct{}{}, &out, 2048); e != nil {
		return scanevidence.JournalBindingRecord{}, e
	}
	created, e := time.Parse(time.RFC3339Nano, out.Document.Created)
	if !out.Valid(c.owner, base) || e != nil || created.After(time.Now()) {
		return scanevidence.JournalBindingRecord{}, errors.New("operator journal binding rejected")
	}
	return out, nil
}

func (c *Client) BrokerBinding(ctx context.Context, base scanevidence.EngineBindingRecord, journal scanevidence.JournalBindingRecord, id string) (scanevidence.BrokerBindingRecord, error) {
	var out scanevidence.BrokerBindingRecord
	if e := c.call(ctx, "engine-broker-binding", struct{}{}, &out, 2048); e != nil {
		return scanevidence.BrokerBindingRecord{}, e
	}
	created, e := time.Parse(time.RFC3339Nano, out.Document.Created)
	if !out.Valid(c.owner, base, journal) || out.Document.Worker != id || e != nil || created.After(time.Now()) {
		return scanevidence.BrokerBindingRecord{}, errors.New("operator broker binding rejected")
	}
	return out, nil
}
