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

type SuiteResult struct {
	Digest   string             `json:"result_digest"`
	Document scanevidence.Suite `json:"document"`
}

// Finish requests derivation from accepted immutable receipts. It carries no
// caller-selected state or cleanup assertion. Expired calls can only replay.
func (c *Client) Finish(ctx context.Context, l Lease, receipts []ReceiptAcknowledgement) (SuiteResult, error) {
	bad := errors.New("scanner suite acknowledgement binding rejected")
	if c.validateBinding(l, false) != nil || len(receipts) != len(l.Job.Input.Tools) {
		return SuiteResult{}, bad
	}
	for i, r := range receipts {
		if r.Schema != "1.0" || r.Job != l.Job.ID || r.Request != l.Job.RequestDigest || r.Tool != l.Job.Input.Tools[i] || !hashPattern.MatchString(r.Digest) || r.State != "accepted" || !r.Cleanup {
			return SuiteResult{}, bad
		}
	}
	var out SuiteResult
	if e := c.call(ctx, "finish", leaseRequest{Job: l.Job.ID, Digest: l.Job.RequestDigest, Token: l.Token}, &out, 32768); e != nil {
		return SuiteResult{}, e
	}
	d := out.Document
	b, _ := json.Marshal(d)
	manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range manifest.Files {
		manifest.Bytes += f.Size
	}
	mb, _ := json.Marshal(manifest)
	stamp, e := time.Parse(time.RFC3339Nano, d.Created)
	started, se := time.Parse(time.RFC3339Nano, l.Job.Created)
	if e != nil || se != nil || stamp.Before(started) || stamp.After(l.Deadline) || d.Schema != "1.0" || d.Owner != l.Job.Owner || d.Job != l.Job.ID || d.Request != l.Job.RequestDigest || d.App != l.Job.Input.App || d.Repository != l.Job.Input.Repository || d.Map != l.Map.Digest || d.Lock != l.Job.LockDigest || d.Snapshot != source.Hash(mb) || d.Tier != "T0" || !d.CleanupRequired || len(d.Tools) != len(receipts) || out.Digest != source.Hash(b) {
		return SuiteResult{}, bad
	}
	for i, t := range d.Tools {
		if t.Tool != receipts[i].Tool || t.Receipt != receipts[i].Digest {
			return SuiteResult{}, bad
		}
	}
	status, claims, partial, stale, toolError, e := scanevidence.Summarize(d.Tools)
	if e != nil || d.Status != status || d.FindingClaims != claims || d.Partial != partial || d.Stale != stale || d.ToolError != toolError {
		return SuiteResult{}, bad
	}
	return out, nil
}
