// SPDX-License-Identifier: Apache-2.0
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/scanqueue"
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

func (s *Server) findingTriage(w http.ResponseWriter, r *http.Request, owner, job string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var out scanqueue.FindingTriageRecord
	var e error
	switch r.Method {
	case "GET":
		values, parse := url.ParseQuery(r.URL.RawQuery)
		if parse != nil || len(values) != 1 || len(values["record_id"]) != 1 {
			fail(w, 400, "VALIDATION_FAILED", "Select one exact finding record")
			return
		}
		out, e = s.Scans.FindingTriage(ctx, owner, job, values.Get("record_id"))
	case "POST":
		if r.URL.RawQuery != "" {
			fail(w, 400, "VALIDATION_FAILED", "Triage mutation does not accept query parameters")
			return
		}
		var in scanqueue.FindingTriageInput
		if auth.Decode(r, &in) != nil {
			fail(w, 400, "VALIDATION_FAILED", "Invalid finding triage request")
			return
		}
		out, e = s.Scans.SetFindingTriage(ctx, owner, job, r.Header.Get("Idempotency-Key"), in)
	default:
		fail(w, 405, "VALIDATION_FAILED", "GET or POST required")
		return
	}
	switch {
	case errors.Is(e, scanqueue.ErrResultUnavailable):
		fail(w, 409, "RESULT_NOT_READY", "No immutable finding evidence is available")
	case errors.Is(e, scanqueue.ErrInput):
		fail(w, 400, "VALIDATION_FAILED", "Provide the exact result, record, revision and a local review rationale")
	case errors.Is(e, scanqueue.ErrFindingBudget):
		fail(w, 422, "RESOURCE_LIMIT", "Finding evidence exceeds its projection budget")
	case e != nil:
		scanError(w, e)
	default:
		output(w, 200, out)
	}
}
