// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/connector"
)

func (s *Server) desktopApproveRenewal(w http.ResponseWriter, r *http.Request, owner, id string) {
	if s.Connectors == nil {
		renewalError(w, connector.ErrRenewalUnavailable)
		return
	}
	receipt, err := s.Connectors.ApproveRenewal(r.Context(), owner, id)
	if err != nil {
		renewalError(w, err)
		return
	}
	output(w, http.StatusOK, receipt)
}

func (s *Server) desktopRenewCredential(w http.ResponseWriter, r *http.Request) {
	if s.Connectors == nil || r.Method != http.MethodPost || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.URL.RawQuery != "" {
		renewalError(w, connector.ErrRenewalUnavailable)
		return
	}
	if !s.pairing.TryLock() {
		renewalError(w, connector.ErrPairingCapacity)
		return
	}
	defer s.pairing.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var in struct {
		Digest string `json:"credential_digest"`
	}
	if auth.Decode(r, &in) != nil {
		fail(w, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid renewal request")
		return
	}
	receipt, err := s.Connectors.Renew(ctx, r.Header.Get("Authorization"), in.Digest)
	if err != nil {
		renewalError(w, err)
		return
	}
	output(w, http.StatusOK, receipt)
}

func renewalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, connector.ErrRenewalUnavailable):
		fail(w, http.StatusNotFound, "RENEWAL_REQUIRED", "No live renewal approval for this credential")
	case errors.Is(err, connector.ErrRenewalConflict):
		fail(w, http.StatusConflict, "CONFLICT", "Renewal does not match the approved rotation")
	case errors.Is(err, connector.ErrPairingCapacity):
		fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "Renewal temporarily unavailable")
	default:
		fail(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "Renewal unavailable")
	}
}
