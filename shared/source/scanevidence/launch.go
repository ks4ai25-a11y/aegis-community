// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"encoding/json"
	"reflect"
)

// LaunchPlan identifies a proposed fixed scanner attempt. Registry is a digest
// of an operator-provisioned private namespace, never a filesystem path.
type LaunchPlan struct {
	Tool         string `json:"tool_id"`
	Container    string `json:"container_id"`
	Engine       string `json:"engine_digest"`
	Workspace    string `json:"workspace_id"`
	Registry     string `json:"registry_digest"`
	Snapshot     string `json:"snapshot_digest"`
	Guard        string `json:"guard_binary_digest,omitempty"`
	Architecture string `json:"guard_architecture,omitempty"`
}
type Launch struct {
	Schema        string     `json:"schema_version"`
	Owner         string     `json:"owner_id"`
	Job           string     `json:"job_id"`
	Request       string     `json:"request_digest"`
	App           string     `json:"app_id"`
	Repository    string     `json:"repository_id"`
	Map           string     `json:"map_digest"`
	Lock          string     `json:"tool_lock_digest"`
	Version       string     `json:"tool_version"`
	Image         string     `json:"tool_image_digest"`
	Profile       string     `json:"sandbox_profile"`
	Duration      int        `json:"duration_limit_seconds"`
	Plan          LaunchPlan `json:"plan"`
	Created       string     `json:"created_at"`
	Deadline      string     `json:"deadline"`
	GuardSet      string     `json:"guard_set_digest,omitempty"`
	GuardProtocol string     `json:"guard_protocol,omitempty"`
}
type LaunchRecord struct {
	Digest   string `json:"launch_digest"`
	Document Launch `json:"document"`
}

type LaunchSubmission struct {
	Schema  string
	Job     string
	Request string
	Token   string `json:"-"`
	Plan    LaunchPlan
}
type launchWire struct {
	Schema  string     `json:"schema_version"`
	Job     string     `json:"job_id"`
	Request string     `json:"request_digest"`
	Token   string     `json:"lease_token"`
	Plan    LaunchPlan `json:"plan"`
}

func DecodeLaunchSubmission(b []byte) (LaunchSubmission, error) {
	var in launchWire
	if len(b) > 8192 || validateJSON(b) != nil || canonicalKeys(b, reflect.TypeOf(in)) != nil || json.Unmarshal(b, &in) != nil {
		return LaunchSubmission{}, ErrReceipt
	}
	return LaunchSubmission{Schema: in.Schema, Job: in.Job, Request: in.Request, Token: in.Token, Plan: in.Plan}, nil
}
func EncodeLaunchSubmission(in LaunchSubmission) ([]byte, error) {
	b, e := json.Marshal(launchWire{Schema: in.Schema, Job: in.Job, Request: in.Request, Token: in.Token, Plan: in.Plan})
	if e != nil || len(b) > 8192 {
		return nil, ErrReceipt
	}
	return b, nil
}
