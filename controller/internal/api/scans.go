// SPDX-License-Identifier: Apache-2.0
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/scanqueue"
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

func scanError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, sql.ErrNoRows):
		fail(w, 404, "RESOURCE_NOT_FOUND", "Scan or owned repository unavailable")
	case errors.Is(e, scanqueue.ErrInput):
		fail(w, 400, "VALIDATION_FAILED", "Provide an owned repository map and supported offline scanner set")
	case errors.Is(e, scanqueue.ErrConflict):
		fail(w, 409, "CONFLICT", "Scan request conflicts with durable identity")
	case errors.Is(e, scanqueue.ErrFull):
		fail(w, 429, "RATE_LIMITED", "Scanner queue budget exhausted")
	default:
		fail(w, 500, "INTERNAL_ERROR", "Scanner state could not be confirmed")
	}
}

func (s *Server) scanOperation(w http.ResponseWriter, r *http.Request, owner, path string) {
	if s.Scans == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Scanner service is not provisioned")
		return
	}
	if path == "/scans" {
		switch r.Method {
		case "POST":
			var in scanqueue.Input
			if auth.Decode(r, &in) != nil {
				fail(w, 400, "VALIDATION_FAILED", "Invalid offline scan request")
				return
			}
			j, e := s.Scans.Enqueue(owner, r.Header.Get("Idempotency-Key"), in)
			if e != nil {
				scanError(w, e)
				return
			}
			w.Header().Set("Location", "/api/v1/scans/"+j.ID)
			output(w, 202, j)
		case "GET":
			jobs, e := s.Scans.List(owner)
			if e != nil {
				scanError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": jobs})
		default:
			fail(w, 405, "VALIDATION_FAILED", "GET or POST required")
		}
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/scans/"), "/")
	if len(parts) > 2 || parts[0] == "" {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Scan operation unavailable")
		return
	}
	id := parts[0]
	// Always establish ownership before reporting result availability.
	if _, e := s.Scans.Get(owner, id); e != nil {
		scanError(w, e)
		return
	}
	if len(parts) == 1 && r.Method == "GET" {
		status, e := s.Scans.Status(owner, id)
		if e != nil {
			scanError(w, e)
			return
		}
		output(w, 200, status)
		return
	}
	if len(parts) == 2 {
		switch {
		case parts[1] == "finding-triage":
			s.findingTriage(w, r, owner, id)
			return
		case parts[1] == "cancel" && r.Method == "POST":
			var body *struct{}
			if auth.Decode(r, &body) != nil || body == nil {
				fail(w, 400, "VALIDATION_FAILED", "Empty object required")
				return
			}
			if e := s.Scans.Cancel(owner, id); e != nil {
				scanError(w, e)
				return
			}
			status, e := s.Scans.Status(owner, id)
			if e != nil {
				scanError(w, e)
				return
			}
			output(w, 200, status)
			return
		case parts[1] == "result" && r.Method == "GET":
			result, e := s.Scans.Result(owner, id)
			if errors.Is(e, sql.ErrNoRows) {
				fail(w, 409, "RESULT_NOT_READY", "No immutable scanner result is available")
				return
			}
			if e != nil {
				scanError(w, e)
				return
			}
			output(w, 200, result)
			return
		}
	}
	fail(w, 404, "RESOURCE_NOT_FOUND", "Scan operation unavailable")
}
