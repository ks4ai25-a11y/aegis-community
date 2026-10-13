// SPDX-License-Identifier: Apache-2.0
package domain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"time"
)

const Version = "0.1.0-alpha.1"

func ID() string {
	u, e := uuid.NewV7()
	if e != nil {
		panic(e)
	}
	return u.String()
}
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// Canonical hashes use Go encoding/json's deterministic sorted map keys. No floats in policies.
func Digest(v any) string  { b, _ := json.Marshal(v); return Hash(b) }
func Hash(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

type CRS struct {
	Blocking  int `json:"blocking_paranoia"`
	Executing int `json:"executing_paranoia"`
	Threshold int `json:"inbound_anomaly_threshold"`
}
type Exclusion struct {
	RuleID    int    `json:"rule_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Parameter string `json:"parameter"`
}
type Metadata struct {
	Rationale   string `json:"rationale"`
	RequestedBy string `json:"requested_by"`
}
type Policy struct {
	Schema     string      `json:"schema_version"`
	Site       string      `json:"site_id"`
	Parent     string      `json:"parent_revision"`
	Mode       string      `json:"requested_mode"`
	CRS        CRS         `json:"crs"`
	Exclusions []Exclusion `json:"exclusions"`
	Metadata   Metadata    `json:"metadata"`
}

func Initial() Policy {
	return Policy{"1.0", "site_demo", "", "observe", CRS{1, 1, 5}, []Exclusion{}, Metadata{"Initial Observe policy", "system"}}
}

type Event struct {
	ID         string   `json:"event_id"`
	Schema     string   `json:"schema_version"`
	At         string   `json:"observed_at"`
	Site       string   `json:"site_id"`
	Request    string   `json:"request_id"`
	Revision   *string  `json:"gateway_revision"`
	Type       string   `json:"event_type"`
	Decision   string   `json:"decision"`
	Method     string   `json:"method,omitempty"`
	Route      string   `json:"route_template,omitempty"`
	Status     *int     `json:"http_status"`
	Rules      []string `json:"rule_ids"`
	Collection string   `json:"collection_status"`
	Privacy    string   `json:"privacy_version"`
	Source     string   `json:"source"`
	Dropped    uint64   `json:"dropped_before"`
	Synthetic  bool     `json:"synthetic"`
}
type Check struct {
	ID              string   `json:"id"`
	Result          string   `json:"result"`
	BaselineStatus  int      `json:"baseline_http_status"`
	CandidateStatus int      `json:"candidate_http_status"`
	Rules           []string `json:"rule_ids"`
	BaselineRules   []string `json:"baseline_rule_ids,omitempty"`
}
type Report struct {
	Schema        string   `json:"schema_version"`
	ID            string   `json:"report_id"`
	Scope         string   `json:"test_scope"`
	ScopeGrant    string   `json:"scope_grant_id,omitempty"`
	Job           string   `json:"job_id,omitempty"`
	ScopeDigest   string   `json:"scope_digest,omitempty"`
	Level         string   `json:"claim_level"`
	Fixture       string   `json:"fixture_id"`
	FixtureDigest string   `json:"fixture_digest"`
	Baseline      string   `json:"baseline_policy_digest"`
	Candidate     string   `json:"candidate_policy_digest"`
	Gateway       string   `json:"gateway_binary_digest"`
	Started       string   `json:"started_at"`
	Completed     string   `json:"completed_at"`
	Checks        []Check  `json:"checks"`
	Overall       string   `json:"overall"`
	Limitations   []string `json:"limitations"`
	Digest        string   `json:"canonical_sha256"`
}
