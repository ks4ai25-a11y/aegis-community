// SPDX-License-Identifier: Apache-2.0
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

func (s *Server) findingCatalogue(w http.ResponseWriter, r *http.Request, owner string) {
	if s.Scans == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Scanner service is not provisioned")
		return
	}
	values, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		fail(w, 400, "VALIDATION_FAILED", "Invalid catalogue filters")
		return
	}
	allowed := map[string]bool{"repository_id": true, "category": true, "severity": true, "limit": true, "cursor": true, "since": true, "until": true}
	for k, v := range values {
		if !allowed[k] || len(v) != 1 {
			fail(w, 400, "VALIDATION_FAILED", "Unknown or repeated catalogue filter")
			return
		}
	}
	limit := 0
	if v, ok := values["limit"]; ok {
		limit, e = strconv.Atoi(v[0])
		if e != nil || limit < 1 || limit > 20 {
			fail(w, 400, "VALIDATION_FAILED", "Finding page limit must be 1–20")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, e := s.Scans.Catalogue(ctx, owner, scanqueue.CatalogueQuery{Repository: values.Get("repository_id"), Category: values.Get("category"), Severity: values.Get("severity"), Since: values.Get("since"), Until: values.Get("until"), Limit: limit, Cursor: values.Get("cursor")})
	switch {
	case errors.Is(e, scanqueue.ErrCatalogueChanged):
		fail(w, 409, "CATALOGUE_CHANGED", "Retained results changed; restart from the first catalogue page")
	case errors.Is(e, scanqueue.ErrInput):
		fail(w, 400, "VALIDATION_FAILED", "Invalid catalogue filters or cursor; restart with a valid time range and page size")
	case errors.Is(e, scanqueue.ErrFindingBudget):
		fail(w, 422, "RESOURCE_LIMIT", "Finding catalogue exceeds its projection budget")
	case e != nil:
		scanError(w, e)
	default:
		output(w, 200, out)
	}
}
