// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var launchContainer = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)
var launchWorkspace = regexp.MustCompile(`^run-[0-9a-f]{32}$`)

// RegisterLaunch must be acknowledged before Docker receives the fixed run
// command. Its exact replay always requires live authority, unlike receipts.
func (c *Client) RegisterLaunch(ctx context.Context, l Lease, p scanevidence.LaunchPlan, version, image string) (scanevidence.LaunchRecord, error) {
	bad := errors.New("scanner launch authorization rejected")
	if c.validate(l) != nil || !launchContainer.MatchString(p.Container) || !launchWorkspace.MatchString(p.Workspace) || !hashPattern.MatchString(p.Engine) || !hashPattern.MatchString(p.Registry) || !hashPattern.MatchString(p.Snapshot) || version == "" || len(version) > 64 || !hashPattern.MatchString(image) {
		return scanevidence.LaunchRecord{}, bad
	}
	selected := false
	for _, tool := range l.Job.Input.Tools {
		if tool == p.Tool {
			selected = true
		}
	}
	if !selected {
		return scanevidence.LaunchRecord{}, bad
	}
	manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
	for _, f := range manifest.Files {
		manifest.Bytes += f.Size
	}
	b, _ := json.Marshal(manifest)
	if p.Snapshot != source.Hash(b) {
		return scanevidence.LaunchRecord{}, bad
	}
	wire, e := scanevidence.EncodeLaunchSubmission(scanevidence.LaunchSubmission{Schema: "1.0", Job: l.Job.ID, Request: l.Job.RequestDigest, Token: l.Token, Plan: p})
	if e != nil {
		return scanevidence.LaunchRecord{}, bad
	}
	var out struct {
		State  string                    `json:"state"`
		Record scanevidence.LaunchRecord `json:"record"`
	}
	if e := c.call(ctx, "launch", json.RawMessage(wire), &out, 8192); e != nil {
		return scanevidence.LaunchRecord{}, e
	}
	d := out.Record.Document
	b, _ = json.Marshal(d)
	stamp, e := time.Parse(time.RFC3339Nano, d.Created)
	started, se := time.Parse(time.RFC3339Nano, l.Job.Created)
	deadline, de := time.Parse(time.RFC3339, d.Deadline)
	if c.validate(l) != nil || e != nil || se != nil || de != nil || stamp.Before(started) || !deadline.Equal(l.Deadline) || !stamp.Before(deadline) || out.State != "authorized" || out.Record.Digest != source.Hash(b) || d.Schema != "1.0" || d.Owner != l.Job.Owner || d.Job != l.Job.ID || d.Request != l.Job.RequestDigest || d.App != l.Job.Input.App || d.Repository != l.Job.Input.Repository || d.Map != l.Map.Digest || d.Lock != l.Job.LockDigest || d.Version != version || d.Image != image || d.Profile != "repo_offline-network-none-v1" || d.Duration != l.Job.Input.Duration || d.Plan != p {
		return scanevidence.LaunchRecord{}, bad
	}
	return out.Record, nil
}
