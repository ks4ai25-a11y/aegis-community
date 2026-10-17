// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"aegis.local/controller/internal/scanqueue"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (s *Server) findings(w http.ResponseWriter, r *http.Request, owner string) {
	if s.Scans == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Scanner service is not provisioned")
		return
	}
	values, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		fail(w, 400, "VALIDATION_FAILED", "Invalid finding filters")
		return
	}
	allowed := map[string]bool{"job_id": true, "category": true, "severity": true, "cursor": true, "limit": true}
	for key, v := range values {
		if !allowed[key] || len(v) != 1 {
			fail(w, 400, "VALIDATION_FAILED", "Unknown or repeated finding filter")
			return
		}
	}
	id := values.Get("job_id")
	if id == "" || len(id) > 80 {
		fail(w, 400, "VALIDATION_FAILED", "Select an owned scan job")
		return
	}
	limit := 0
	if raw, ok := values["limit"]; ok {
		limit, e = strconv.Atoi(raw[0])
		if e != nil || limit < 1 || limit > 20 {
			fail(w, 400, "VALIDATION_FAILED", "Finding page limit must be 1–20")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, e := s.Scans.Findings(ctx, owner, id, scanqueue.FindingQuery{Category: values.Get("category"), Severity: values.Get("severity"), Cursor: values.Get("cursor"), Limit: limit})
	switch {
	case errors.Is(e, scanqueue.ErrInput):
		fail(w, 400, "VALIDATION_FAILED", "Finding filters or cursor do not match this result; start from the first page")
	case errors.Is(e, scanqueue.ErrResultUnavailable):
		fail(w, 409, "RESULT_NOT_READY", "No immutable scanner result is available")
	case errors.Is(e, scanqueue.ErrFindingBudget):
		fail(w, 422, "RESOURCE_LIMIT", "Finding aggregation or provenance exceeds its budget")
	case e != nil:
		scanError(w, e)
	default:
		output(w, 200, out)
	}
}
