// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/redteam"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source/scanevidence"
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
	case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/research-plan") && r.Method == "POST":
		s.researchPlan(w, r, owner, strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"), "/research-plan"))
	case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/rescan") && (r.Method == "GET" || r.Method == "POST"):
		s.rescanPolicy(w, r, owner, strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"), "/rescan"))
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

// rescanPolicy reads or sets the owner's change-triggered rescan opt-in (D9).
func (s *Server) rescanPolicy(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if s.Scans == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Scanner service is not provisioned")
		return
	}
	if r.Method == "GET" {
		p, e := s.Scans.RescanPolicyFor(owner, repo)
		if e != nil {
			s.repositoryError(w, e)
			return
		}
		output(w, 200, p)
		return
	}
	var in struct {
		Enabled  bool     `json:"enabled"`
		Tools    []string `json:"tool_ids"`
		Duration int      `json:"tool_timeout_seconds"`
	}
	if auth.Decode(r, &in) != nil {
		fail(w, 400, "VALIDATION_FAILED", "Provide enabled, tool_ids and tool_timeout_seconds")
		return
	}
	p, e := s.Scans.SetRescanPolicy(owner, repo, in.Enabled, in.Tools, in.Duration)
	switch {
	case errors.Is(e, scanqueue.ErrPolicy):
		fail(w, 400, "VALIDATION_FAILED", "Choose one to six supported scanners and a timeout of 1 to 120 seconds")
	case errors.Is(e, scanqueue.ErrFull):
		fail(w, 422, "RESOURCE_LIMIT", "Too many repositories have automatic rescans enabled")
	case e != nil:
		s.repositoryError(w, e)
	default:
		output(w, 200, p)
	}
}

// researchPlan runs the safe red research planner (D5) over the repository's
// current application map and its latest retained findings. It plans only;
// tests run through the research queue after separate owner approval.
func (s *Server) researchPlan(w http.ResponseWriter, r *http.Request, owner, repo string) {
	var in struct {
		UseModel bool `json:"use_model"`
	}
	if auth.Decode(r, &in) != nil {
		fail(w, 400, "VALIDATION_FAILED", "Invalid research plan request")
		return
	}
	m, e := s.R.Map(owner, repo)
	if e != nil {
		s.repositoryError(w, e)
		return
	}
	findings := []scanevidence.Finding{}
	unavailable := s.Scans == nil
	if s.Scans != nil {
		// The catalogue pages at most 20 findings; read up to three pages.
		cursor := ""
		for i := 0; i < 3; i++ {
			page, e := s.Scans.Catalogue(r.Context(), owner, scanqueue.CatalogueQuery{Repository: repo, Limit: 20, Cursor: cursor})
			if e != nil {
				unavailable = true
				break
			}
			if page.Findings != nil {
				for _, item := range page.Findings.Items {
					findings = append(findings, item.Finding)
				}
			}
			if cursor = page.Next; cursor == "" {
				break
			}
		}
	}
	select {
	case s.assessing <- struct{}{}:
		defer func() { <-s.assessing }()
	default:
		fail(w, 429, "RATE_LIMITED", "Another model request is running")
		return
	}
	excerpt := func(path string, line int) (repository.Excerpt, error) {
		return s.R.Excerpt(owner, repo, path, line, 8)
	}
	ps := redteam.Run(r.Context(), s.AI, redteam.Inputs{Repository: repo, Map: m, Findings: findings, FindingsUnavailable: unavailable, Excerpt: excerpt}, in.UseModel)
	if e = s.S.Audit(owner, "research.plan", repo, ps.Planner, map[string]any{"plan_set_digest": ps.Digest, "map_digest": ps.MapDigest, "plans": len(ps.Plans), "rejected": len(ps.Rejected), "model": ps.Model}); e != nil {
		fail(w, 500, "INTERNAL_ERROR", "Research plan audit unavailable")
		return
	}
	output(w, 200, ps)
}
