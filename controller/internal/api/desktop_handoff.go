// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"errors"
	"net/http"
	"strings"

	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/connector"
)

func (s *Server) desktopHandoff(w http.ResponseWriter, r *http.Request, path, owner, session, connection string) {
	if s.Connectors == nil {
		fail(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "Desktop handoffs unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	const base = "/desktop/handoffs"
	switch {
	case session != "" && path == "/desktop/handoff-preview" && r.Method == http.MethodGet:
		p, err := s.Connectors.PreviewHandoff(ctx, r.URL.Query().Get("incident_id"))
		if err != nil {
			handoffError(w, err)
			return
		}
		output(w, http.StatusOK, p)
	case session != "" && path == base && r.Method == http.MethodPost:
		var in struct {
			Incident  string `json:"incident_id"`
			Connector string `json:"connector_id"`
			Digest    string `json:"preview_digest"`
			Consent   bool   `json:"approve_redacted_export"`
		}
		if auth.Decode(r, &in) != nil || in.Incident == "" || in.Connector == "" || in.Digest == "" {
			fail(w, http.StatusBadRequest, "VALIDATION_FAILED", "Select an incident preview and a connector")
			return
		}
		if !in.Consent {
			fail(w, http.StatusForbidden, "CONSENT_REQUIRED", "Approve the redacted incident preview before sharing")
			return
		}
		h, err := s.Connectors.ApproveHandoff(ctx, owner, in.Connector, in.Incident, in.Digest)
		if err != nil {
			handoffError(w, err)
			return
		}
		output(w, http.StatusCreated, h)
	case session != "" && strings.HasPrefix(path, base+"/") && strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, base+"/"), "/revoke")
		if err := s.Connectors.RevokeHandoff(ctx, owner, id); err != nil {
			handoffError(w, err)
			return
		}
		output(w, http.StatusOK, map[string]string{"state": "revoked"})
	case connection != "" && strings.HasPrefix(path, base+"/") && r.Method == http.MethodGet:
		b, err := s.Connectors.ReadHandoff(ctx, owner, connection, strings.TrimPrefix(path, base+"/"))
		if err != nil {
			handoffError(w, err)
			return
		}
		output(w, http.StatusOK, b)
	default:
		fail(w, http.StatusForbidden, "SCOPE_DENIED", "Desktop handoff scope denied")
	}
}

func handoffError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, connector.ErrHandoffChanged):
		fail(w, http.StatusConflict, "STALE_HANDOFF", "Incident preview changed. Review it again before sharing.")
	case errors.Is(err, connector.ErrHandoffUnavailable):
		fail(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Handoff or incident unavailable")
	case errors.Is(err, connector.ErrHandoffLimit):
		fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "Handoff capacity reached")
	default:
		fail(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "Desktop handoffs unavailable")
	}
}
