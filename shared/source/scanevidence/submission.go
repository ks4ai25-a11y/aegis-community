// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"encoding/json"
	"reflect"
	"regexp"
)

const MaxSubmission = MaxOutput + 4096

var submissionJob = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var submissionToken = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Document binds immutable evidence to its owner, job and request namespace.
type Document struct {
	Schema    string    `json:"schema_version"`
	Owner     string    `json:"owner_id"`
	Job       string    `json:"job_id"`
	Request   string    `json:"request_digest"`
	Execution Execution `json:"execution"`
}

// Submission never exports its capability through general JSON serialization.
// EncodeSubmission is the explicit private-channel serialization operation.
type Submission struct {
	Job, Request string
	Token        string `json:"-"`
	Execution    Execution
}
type submissionWire struct {
	Schema    string          `json:"schema_version"`
	Job       string          `json:"job_id"`
	Request   string          `json:"request_digest"`
	Token     string          `json:"lease_token"`
	Execution json.RawMessage `json:"execution"`
}

func DecodeSubmission(b []byte) (Submission, error) {
	var wire submissionWire
	if validateJSONSize(b, MaxSubmission) != nil || canonicalKeys(b, reflect.TypeOf(wire)) != nil || json.Unmarshal(b, &wire) != nil || wire.Schema != "1.0" || !submissionJob.MatchString(wire.Job) || !hash.MatchString(wire.Request) || !submissionToken.MatchString(wire.Token) {
		return Submission{}, ErrReceipt
	}
	r, e := Decode(wire.Execution)
	if e != nil {
		return Submission{}, ErrReceipt
	}
	return Submission{wire.Job, wire.Request, wire.Token, r}, nil
}
func EncodeSubmission(in Submission) ([]byte, error) {
	execution, e := json.Marshal(in.Execution)
	if e != nil {
		return nil, ErrReceipt
	}
	b, e := json.Marshal(submissionWire{"1.0", in.Job, in.Request, in.Token, execution})
	if e != nil {
		return nil, ErrReceipt
	}
	if _, e = DecodeSubmission(b); e != nil {
		return nil, ErrReceipt
	}
	return b, nil
}
