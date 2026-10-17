// SPDX-License-Identifier: BUSL-1.1
// Package brokerwire contains only bounded dispatch metadata. It has no engine,
// worker enrollment, source execution or controller database dependency.
package brokerwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

const RunPath = "/internal/v1/scanner-broker/run-once"

var hash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var job = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var ErrProtocol = errors.New("broker dispatch response refused")

type Outcome struct {
	Schema    string `json:"schema_version"`
	State     string `json:"state"`
	Job       string `json:"job_id,omitempty"`
	Request   string `json:"request_digest,omitempty"`
	Result    string `json:"result_digest,omitempty"`
	Receipts  int    `json:"receipt_count"`
	AllWrites bool   `json:"all_engine_writes_mediated"`
	Release   bool   `json:"cleanup_release_authorized"`
}

func (o Outcome) Valid() bool {
	if o.Schema != "1.0" || o.Receipts < 0 || o.Receipts > 6 || o.AllWrites || o.Release {
		return false
	}
	switch o.State {
	case "not_claimed", "no_job":
		return o.Job == "" && o.Request == "" && o.Result == "" && o.Receipts == 0
	case "stopped", "finalization_unconfirmed":
		return job.MatchString(o.Job) && hash.MatchString(o.Request) && o.Result == ""
	case "completed", "completed_partial", "completed_stale_db", "tool_error":
		return job.MatchString(o.Job) && hash.MatchString(o.Request) && hash.MatchString(o.Result) && o.Receipts > 0
	}
	return false
}
func Decode(raw []byte) (Outcome, error) {
	var out Outcome
	if len(raw) > 4096 || json.Unmarshal(raw, &out) != nil || !out.Valid() {
		return Outcome{}, ErrProtocol
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return Outcome{}, ErrProtocol
	}
	return out, nil
}
