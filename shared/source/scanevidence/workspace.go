// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"encoding/json"
	"reflect"
)

// WorkspacePlan reserves an opaque run ID in a provisioned namespace before
// any run directory or source snapshot is created. It contains no host paths.
type WorkspacePlan struct {
	Tool      string `json:"tool_id"`
	Workspace string `json:"workspace_id"`
	Registry  string `json:"registry_digest"`
	Snapshot  string `json:"snapshot_digest"`
}
type Workspace struct {
	Schema     string        `json:"schema_version"`
	Owner      string        `json:"owner_id"`
	Job        string        `json:"job_id"`
	Request    string        `json:"request_digest"`
	App        string        `json:"app_id"`
	Repository string        `json:"repository_id"`
	Map        string        `json:"map_digest"`
	Lock       string        `json:"tool_lock_digest"`
	Plan       WorkspacePlan `json:"plan"`
	Created    string        `json:"created_at"`
	Deadline   string        `json:"deadline"`
}
type WorkspaceRecord struct {
	Digest   string    `json:"workspace_digest"`
	Document Workspace `json:"document"`
}

type WorkspaceSubmission struct {
	Schema  string
	Job     string
	Request string
	Token   string `json:"-"`
	Plan    WorkspacePlan
}
type workspaceWire struct {
	Schema  string        `json:"schema_version"`
	Job     string        `json:"job_id"`
	Request string        `json:"request_digest"`
	Token   string        `json:"lease_token"`
	Plan    WorkspacePlan `json:"plan"`
}

func DecodeWorkspaceSubmission(b []byte) (WorkspaceSubmission, error) {
	var in workspaceWire
	if len(b) > 8192 || validateJSON(b) != nil || canonicalKeys(b, reflect.TypeOf(in)) != nil || json.Unmarshal(b, &in) != nil {
		return WorkspaceSubmission{}, ErrReceipt
	}
	return WorkspaceSubmission{Schema: in.Schema, Job: in.Job, Request: in.Request, Token: in.Token, Plan: in.Plan}, nil
}
func EncodeWorkspaceSubmission(in WorkspaceSubmission) ([]byte, error) {
	b, e := json.Marshal(workspaceWire{Schema: in.Schema, Job: in.Job, Request: in.Request, Token: in.Token, Plan: in.Plan})
	if e != nil || len(b) > 8192 {
		return nil, ErrReceipt
	}
	return b, nil
}
