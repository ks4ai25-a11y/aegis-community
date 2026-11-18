// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/connector"
)

func (s *Server) desktopDraft(w http.ResponseWriter, r *http.Request, path, owner, session, connection string) {
	if s.Connectors == nil {
		fail(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "Desktop drafts unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	const base = "/desktop/drafts"
	switch {
	case path == base && r.Method == http.MethodPost && connection != "":
		var in struct {
			connector.DraftDocument
			IdempotencyKey string `json:"idempotency_key"`
		}
		if auth.Decode(r, &in) != nil {
			fail(w, http.StatusBadRequest, "DRAFT_SCHEMA_INVALID", "Invalid draft")
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			key = in.IdempotencyKey
		}
		if in.IdempotencyKey != "" && key != in.IdempotencyKey {
			fail(w, http.StatusBadRequest, "DRAFT_SCHEMA_INVALID", "Idempotency keys do not match")
			return
		}
		d, replay, err := s.Connectors.SubmitDraft(ctx, owner, connection, key, in.DraftDocument)
		if err != nil {
			desktopDraftError(w, err)
			return
		}
		if replay {
			output(w, http.StatusOK, d)
			return
		}
		output(w, http.StatusCreated, d)
	case path == base && r.Method == http.MethodGet && session != "":
		items, err := s.Connectors.ListDrafts(ctx, owner, r.URL.Query().Get("incident_id"))
		if err != nil {
			desktopDraftError(w, err)
			return
		}
		output(w, http.StatusOK, map[string]any{"items": items})
	case path != base && r.Method == http.MethodGet && connection != "":
		d, err := s.Connectors.ConnectorDraftStatus(ctx, owner, connection, strings.TrimPrefix(path, base+"/"))
		if err != nil {
			desktopDraftError(w, err)
			return
		}
		output(w, http.StatusOK, d)
	case path != base && r.Method == http.MethodPost && session != "" && strings.HasSuffix(path, "/dismiss"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, base+"/"), "/dismiss")
		if err := s.Connectors.DismissDraft(ctx, owner, id); err != nil {
			desktopDraftError(w, err)
			return
		}
		output(w, http.StatusOK, connector.DraftStatus{ID: id, State: "dismissed"})
	default:
		fail(w, http.StatusForbidden, "SCOPE_DENIED", "Desktop draft scope denied")
	}
}

func desktopDraftError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, connector.ErrDraftConsent):
		fail(w, http.StatusForbidden, "CONSENT_REQUIRED", "Draft submission requires an active approved handoff")
	case errors.Is(err, connector.ErrDraftInvalid):
		fail(w, http.StatusBadRequest, "DRAFT_SCHEMA_INVALID", "Invalid draft or idempotency key")
	case errors.Is(err, connector.ErrDraftSource):
		fail(w, http.StatusBadRequest, "SOURCE_ID_INVALID", "A claim references evidence outside the approved snapshot")
	case errors.Is(err, connector.ErrDraftConflict):
		fail(w, http.StatusConflict, "CONFLICT", "Submission conflicts with an existing draft")
	case errors.Is(err, connector.ErrDraftLimit):
		fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "Draft storage limit reached")
	case errors.Is(err, sql.ErrNoRows):
		fail(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "Draft unavailable")
	default:
		fail(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "Desktop drafts unavailable")
	}
}
