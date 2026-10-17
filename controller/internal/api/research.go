// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/research"
	"aegis.local/controller/internal/scope"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func researchError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, sql.ErrNoRows):
		fail(w, 404, "RESOURCE_NOT_FOUND", "Record not found")
	case errors.Is(e, research.ErrConflict):
		fail(w, 409, "CONFLICT", "Request conflicts with durable state")
	case errors.Is(e, research.ErrScope):
		fail(w, 403, "SCOPE_NOT_ALLOWED", "Scope is inactive, expired, exhausted, revoked or unowned")
	case errors.Is(e, research.ErrFull):
		fail(w, 429, "RATE_LIMITED", "Research queue is full")
	default:
		fail(w, 500, "INTERNAL_ERROR", "Research state could not be confirmed")
	}
}
func (s *Server) scopeOperation(w http.ResponseWriter, r *http.Request, actor, path string) {
	if s.Q == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Research unavailable")
		return
	}
	if path == "/scope-grants" {
		if r.Method == "POST" {
			var in struct {
				App     string `json:"app_id"`
				Mode    string `json:"mode"`
				Fixture string `json:"fixture_id"`
				Minutes int    `json:"lifetime_minutes"`
			}
			if auth.Decode(r, &in) != nil || in.App != "app_demo" || in.Mode != "test_lab" || in.Fixture != scope.Fixture || in.Minutes < 1 || in.Minutes > 60 {
				fail(w, 400, "VALIDATION_FAILED", "Only the bundled test_lab fixture is currently available, for 1–60 minutes")
				return
			}
			g, e := s.Q.CreateGrant(actor, in.Minutes)
			if e != nil {
				researchError(w, e)
				return
			}
			output(w, 201, g)
			return
		}
		if r.Method == "GET" {
			rows, e := s.S.DB.Query("SELECT document,digest,state,requests_used FROM scope_grants WHERE owner=? ORDER BY created_at DESC,id DESC LIMIT 100", actor)
			if e != nil {
				researchError(w, e)
				return
			}
			defer rows.Close()
			out := []research.GrantRecord{}
			for rows.Next() {
				var b string
				var used int
				var g research.GrantRecord
				if e = rows.Scan(&b, &g.Digest, &g.State, &used); e != nil {
					researchError(w, e)
					return
				}
				if e = json.Unmarshal([]byte(b), &g.Grant); e != nil || domain.Digest(g.Grant) != g.Digest {
					fail(w, 500, "INTERNAL_ERROR", "Scope integrity mismatch")
					return
				}
				g.RequestsRemaining = g.Grant.Requests - used
				out = append(out, g)
			}
			if e = rows.Err(); e != nil {
				researchError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": out})
			return
		}
		fail(w, 405, "VALIDATION_FAILED", "GET or POST required")
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/scope-grants/"), "/")
	if len(parts) == 1 && r.Method == "GET" {
		g, e := s.Q.Grant(actor, parts[0])
		if e != nil {
			researchError(w, e)
			return
		}
		output(w, 200, g)
		return
	}
	if len(parts) != 2 || r.Method != "POST" {
		fail(w, 404, "RESOURCE_NOT_FOUND", "Scope operation not found")
		return
	}
	switch parts[1] {
	case "approve":
		var in struct {
			Digest string `json:"approved_digest"`
			Ack    bool   `json:"acknowledge_test_scope"`
		}
		if auth.Decode(r, &in) != nil || !in.Ack {
			fail(w, 400, "VALIDATION_FAILED", "Exact digest and explicit scope acknowledgement required")
			return
		}
		g, e := s.Q.Approve(actor, parts[0], in.Digest, in.Ack)
		if e != nil {
			researchError(w, e)
			return
		}
		output(w, 200, g)
	case "revoke":
		var in struct{}
		if auth.Decode(r, &in) != nil {
			fail(w, 400, "VALIDATION_FAILED", "Empty JSON object required")
			return
		}
		if e := s.Q.Revoke(actor, parts[0]); e != nil {
			researchError(w, e)
			return
		}
		output(w, 200, map[string]string{"state": "revoked"})
	default:
		fail(w, 404, "RESOURCE_NOT_FOUND", "Scope operation not found")
	}
}
func (s *Server) enqueueVerification(w http.ResponseWriter, r *http.Request, actor string) {
	if s.Q == nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Research unavailable")
		return
	}
	var in research.Input
	if auth.Decode(r, &in) != nil || in.Schema != "1.0" || in.App != "app_demo" || in.Fixture != scope.Fixture || len(r.Header.Get("Idempotency-Key")) < 8 || len(r.Header.Get("Idempotency-Key")) > 128 {
		fail(w, 400, "VALIDATION_FAILED", "Typed fixture input, approved scope and idempotency key required")
		return
	}
	j, e := s.Q.Enqueue(actor, r.Header.Get("Idempotency-Key"), in)
	if e != nil {
		researchError(w, e)
		return
	}
	w.Header().Set("Location", "/api/v1/verifications/"+j.ID)
	output(w, 202, j)
}
func (s *Server) listJobs(w http.ResponseWriter, actor string) {
	j, e := s.Q.List(actor)
	if e != nil {
		researchError(w, e)
		return
	}
	output(w, 200, map[string]any{"items": j})
}
func (s *Server) jobOperation(w http.ResponseWriter, r *http.Request, actor, suffix string) {
	parts := strings.Split(suffix, "/")
	if len(parts) == 1 && r.Method == "GET" {
		j, e := s.Q.Get(actor, parts[0])
		if e != nil {
			researchError(w, e)
			return
		}
		output(w, 200, j)
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == "POST" {
		var in struct{}
		if auth.Decode(r, &in) != nil {
			fail(w, 400, "VALIDATION_FAILED", "Empty JSON object required")
			return
		}
		if e := s.Q.Cancel(actor, parts[0]); e != nil {
			researchError(w, e)
			return
		}
		j, e := s.Q.Get(actor, parts[0])
		if e != nil {
			researchError(w, e)
			return
		}
		output(w, 200, j)
		return
	}
	fail(w, 404, "RESOURCE_NOT_FOUND", "Job operation not found")
}
func (s *Server) reportDocument(w http.ResponseWriter, actor, digest string) {
	var raw string
	e := s.S.DB.QueryRow("SELECT r.document FROM reports r JOIN report_owners o ON o.digest=r.digest WHERE r.digest=? AND o.owner=?", digest, actor).Scan(&raw)
	if e != nil {
		researchError(w, e)
		return
	}
	output(w, 200, json.RawMessage(raw))
}
