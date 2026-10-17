// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"errors"
	"time"
)

type ReceiptAcknowledgement struct {
	Schema  string `json:"schema_version"`
	Job     string `json:"job_id"`
	Request string `json:"request_digest"`
	Tool    string `json:"tool_id"`
	Digest  string `json:"receipt_digest"`
	State   string `json:"state"`
	Cleanup bool   `json:"cleanup_required"`
}

// SubmitReceipt normalizes before upload and verifies the exact owner/job-bound
// content digest in the acknowledgement. Replay is permitted after the original
// deadline; only the controller can accept an already committed record then.
// Acceptance neither completes a job nor independently confirms cleanup.
func (c *Client) SubmitReceipt(ctx context.Context, l Lease, r scanevidence.Execution) (ReceiptAcknowledgement, error) {
	if c.validateBinding(l, false) != nil {
		return ReceiptAcknowledgement{}, errors.New("invalid receipt lease binding")
	}
	started, e := time.Parse(time.RFC3339Nano, l.Job.Created)
	if e != nil {
		return ReceiptAcknowledgement{}, errors.New("invalid receipt job timestamp")
	}
	normalized, e := scanevidence.Normalize(r, scanevidence.Expected{Tools: l.Job.Input.Tools, App: l.Job.Input.App, Repository: l.Job.Input.Repository, LockDigest: c.lock, Tool: r.Tool, Version: r.Version, Image: r.Image, Timeout: l.Job.Input.Duration, Map: l.Map, NotBefore: started, NotAfter: time.Now().UTC(), Database: l.Job.Input.Databases[r.Tool]})
	if e != nil {
		return ReceiptAcknowledgement{}, errors.New("invalid scanner receipt")
	}
	b, e := scanevidence.EncodeSubmission(scanevidence.Submission{Job: l.Job.ID, Request: l.Job.RequestDigest, Token: l.Token, Execution: normalized})
	if e != nil {
		return ReceiptAcknowledgement{}, errors.New("invalid scanner receipt")
	}
	var ack ReceiptAcknowledgement
	if e = c.call(ctx, "receipt", json.RawMessage(b), &ack, 8192); e != nil {
		return ReceiptAcknowledgement{}, e
	}
	doc, _ := json.Marshal(scanevidence.Document{Schema: "1.0", Owner: l.Job.Owner, Job: l.Job.ID, Request: l.Job.RequestDigest, Execution: normalized})
	if ack.Schema != "1.0" || ack.Job != l.Job.ID || ack.Request != l.Job.RequestDigest || ack.Tool != r.Tool || ack.State != "accepted" || !ack.Cleanup || ack.Digest != source.Hash(doc) {
		return ReceiptAcknowledgement{}, errors.New("scanner receipt acknowledgement binding rejected")
	}
	return ack, nil
}
