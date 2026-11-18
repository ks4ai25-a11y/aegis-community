// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/connector"
)

func (s *Server) desktopPairingBridge(w http.ResponseWriter, r *http.Request, path string) {
	if s.Connectors == nil || r.Method != http.MethodPost || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" ||
		r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
		pairingError(w, connector.ErrPairingUnavailable)
		return
	}
	if !s.pairing.TryLock() {
		pairingError(w, connector.ErrPairingCapacity)
		return
	}
	defer s.pairing.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if path == "/desktop/pairing/claim" {
		var in struct {
			ID          string `json:"pairing_id"`
			Code        string `json:"invite_code"`
			Proof       string `json:"device_proof"`
			TokenDigest string `json:"credential_digest"`
		}
		if auth.Decode(r, &in) != nil {
			pairingError(w, connector.ErrPairingInput)
			return
		}
		if err := s.Connectors.ClaimPairing(ctx, in.ID, in.Code, in.Proof, in.TokenDigest); err != nil {
			pairingError(w, err)
			return
		}
		output(w, http.StatusOK, map[string]string{"state": "claimed"})
		return
	}
	var in struct {
		ID    string `json:"pairing_id"`
		Proof string `json:"device_proof"`
	}
	if auth.Decode(r, &in) != nil {
		pairingError(w, connector.ErrPairingInput)
		return
	}
	credential, err := s.Connectors.RedeemPairing(ctx, in.ID, in.Proof)
	if err != nil {
		pairingError(w, err)
		return
	}
	output(w, http.StatusOK, credential)
}

func (s *Server) desktopPairingOwner(w http.ResponseWriter, r *http.Request, path, owner, session string) {
	if s.Connectors == nil || session == "" {
		pairingError(w, connector.ErrPairingUnavailable)
		return
	}
	ctx := r.Context()
	const base = "/desktop/pairing"
	switch {
	case path == base && r.Method == http.MethodPost:
		var in struct {
			Name    string `json:"name"`
			Minutes int    `json:"lifetime_minutes"`
			Draft   bool   `json:"allow_analysis_draft"`
		}
		if auth.Decode(r, &in) != nil {
			pairingError(w, connector.ErrPairingInput)
			return
		}
		p, code, err := s.Connectors.Invite(ctx, owner, in.Name, in.Minutes, in.Draft)
		if err != nil {
			pairingError(w, err)
			return
		}
		output(w, http.StatusCreated, map[string]any{"pairing": p, "invite_code": code})
	case path != base && r.Method == http.MethodGet:
		p, err := s.Connectors.Pairing(ctx, owner, strings.TrimPrefix(path, base+"/"))
		if err != nil {
			pairingError(w, err)
			return
		}
		output(w, http.StatusOK, p)
	case path != base && r.Method == http.MethodPost:
		var in struct {
			Fingerprint string `json:"fingerprint"`
			Approve     *bool  `json:"approve"`
		}
		if auth.Decode(r, &in) != nil || in.Approve == nil {
			pairingError(w, connector.ErrPairingInput)
			return
		}
		if err := s.Connectors.DecidePairing(ctx, owner, strings.TrimPrefix(path, base+"/"), in.Fingerprint, *in.Approve); err != nil {
			pairingError(w, err)
			return
		}
		output(w, http.StatusOK, map[string]bool{"approved": *in.Approve})
	default:
		pairingError(w, connector.ErrPairingUnavailable)
	}
}

func pairingError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, connector.ErrPairingUnavailable):
		fail(w, http.StatusNotFound, "PAIRING_REQUIRED", "Pairing invitation unavailable")
	case errors.Is(err, connector.ErrPairingInput):
		fail(w, http.StatusBadRequest, "VALIDATION_FAILED", "Invalid pairing request")
	case errors.Is(err, connector.ErrPairingPending):
		fail(w, http.StatusConflict, "PAIRING_REQUIRED", "Owner confirmation pending")
	case errors.Is(err, connector.ErrPairingCapacity):
		fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "Pairing capacity reached")
	default:
		fail(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "Pairing unavailable")
	}
}
