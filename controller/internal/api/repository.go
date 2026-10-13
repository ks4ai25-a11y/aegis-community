// SPDX-License-Identifier: Apache-2.0
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/repository"
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

func (s *Server) repositoryOperation(w http.ResponseWriter, r *http.Request, owner, path string) {
	if s.R == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Repository mounts are not provisioned")
		return
	}
	switch {
	case path == "/repos/assets" && r.Method == "GET":
		assets, e := s.R.Assets(owner)
		if e != nil {
			s.repositoryError(w, e)
			return
		}
		output(w, 200, map[string]any{"asset_ids": assets})
	case path == "/repos" && r.Method == "POST":
		var in struct {
			App         string `json:"app_id"`
			Asset       string `json:"asset_id"`
			Acknowledge bool   `json:"acknowledge_read_only"`
		}
		if auth.Decode(r, &in) != nil {
			fail(w, 400, "VALIDATION_FAILED", "Provide an approved mount asset and read-only acknowledgement")
			return
		}
		out, e := s.R.ConnectContext(r.Context(), owner, in.App, in.Asset, in.Acknowledge)
		if e != nil {
			s.repositoryError(w, e)
			return
		}
		w.Header().Set("Location", "/api/v1/repos/"+out.ID)
		output(w, 201, out)
	case path == "/repos" && r.Method == "GET":
		out, e := s.R.List(owner)
		if e != nil {
			s.repositoryError(w, e)
			return
		}
		output(w, 200, map[string]any{"items": out})
	case strings.HasPrefix(path, "/repos/") && r.Method == "GET":
		rest := strings.TrimPrefix(path, "/repos/")
		if strings.HasSuffix(rest, "/map") {
			out, e := s.R.Map(owner, strings.TrimSuffix(rest, "/map"))
			if e != nil {
				s.repositoryError(w, e)
				return
			}
			output(w, 200, out)
			return
		}
		out, e := s.R.Get(owner, rest)
		if e != nil {
			s.repositoryError(w, e)
			return
		}
		output(w, 200, out)
	default:
		fail(w, 404, "NOT_FOUND", "Repository operation unavailable")
	}
}
func (s *Server) repositoryError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, sql.ErrNoRows):
		fail(w, 404, "NOT_FOUND", "Repository unavailable")
	case errors.Is(e, repository.ErrUnavailable):
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Repository mounts are not provisioned")
	case errors.Is(e, repository.ErrBudget):
		fail(w, 422, "RESOURCE_LIMIT", "Repository map or retained history exceeds its budget")
	case errors.Is(e, repository.ErrAsset):
		fail(w, 400, "VALIDATION_FAILED", "Repository asset or source boundary validation failed")
	default:
		fail(w, 500, "INTERNAL_ERROR", "Repository persistence unavailable")
	}
}
