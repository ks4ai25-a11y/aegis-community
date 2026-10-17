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

// ReserveWorkspace must be acknowledged before the named run directory exists.
// The acknowledgement is intent metadata, never a cleanup attestation.
func (c *Client) ReserveWorkspace(ctx context.Context, l Lease, p scanevidence.WorkspacePlan) (scanevidence.WorkspaceRecord, error) {
	bad := errors.New("scanner workspace reservation rejected")
	if c.validate(l) != nil || !launchWorkspace.MatchString(p.Workspace) || !hashPattern.MatchString(p.Registry) || !hashPattern.MatchString(p.Snapshot) {
		return scanevidence.WorkspaceRecord{}, bad
	}
	selected := false
	for _, tool := range l.Job.Input.Tools {
		if tool == p.Tool {
			selected = true
		}
	}
	if !selected {
		return scanevidence.WorkspaceRecord{}, bad
	}
	manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range manifest.Files {
		manifest.Bytes += f.Size
	}
	b, _ := json.Marshal(manifest)
	if p.Snapshot != source.Hash(b) {
		return scanevidence.WorkspaceRecord{}, bad
	}
	wire, e := scanevidence.EncodeWorkspaceSubmission(scanevidence.WorkspaceSubmission{Schema: "1.0", Job: l.Job.ID, Request: l.Job.RequestDigest, Token: l.Token, Plan: p})
	if e != nil {
		return scanevidence.WorkspaceRecord{}, bad
	}
	var out struct {
		State  string                       `json:"state"`
		Record scanevidence.WorkspaceRecord `json:"record"`
	}
	if e = c.call(ctx, "workspace", json.RawMessage(wire), &out, 8192); e != nil {
		return scanevidence.WorkspaceRecord{}, e
	}
	d := out.Record.Document
	b, _ = json.Marshal(d)
	stamp, se := time.Parse(time.RFC3339Nano, d.Created)
	queued, qe := time.Parse(time.RFC3339Nano, l.Job.Created)
	deadline, de := time.Parse(time.RFC3339, d.Deadline)
	if c.validate(l) != nil || se != nil || qe != nil || de != nil || stamp.Before(queued) || !deadline.Equal(l.Deadline) || !stamp.Before(deadline) || out.State != "reserved" || out.Record.Digest != source.Hash(b) || d.Schema != "1.0" || d.Owner != l.Job.Owner || d.Job != l.Job.ID || d.Request != l.Job.RequestDigest || d.App != l.Job.Input.App || d.Repository != l.Job.Input.Repository || d.Map != l.Map.Digest || d.Lock != l.Job.LockDigest || d.Plan != p {
		return scanevidence.WorkspaceRecord{}, bad
	}
	return out.Record, nil
}
