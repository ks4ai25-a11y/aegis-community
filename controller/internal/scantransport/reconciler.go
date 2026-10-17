// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) reconciler(w http.ResponseWriter, r *http.Request, token string) {
	if len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
		failure(w, 400, "INVALID_RECONCILER_REQUEST")
		return
	}
	v, err := s.Auth.AuthenticateReconciler(token)
	if err != nil {
		failure(w, 401, "RECONCILER_AUTH_REQUIRED")
		return
	}
	switch r.URL.Path {
	case "/internal/v1/scanner/reconciler/identity":
		if authorizerDecode(r, &struct{}{}, nil) != nil {
			failure(w, 400, "INVALID_RECONCILER_REQUEST")
			return
		}
		reply(w, 200, v)
	case "/internal/v1/scanner/reconciler/context":
		var in scanevidence.ReconciliationRequest
		if authorizerDecode(r, &in, map[string]bool{"job_id": true, "generation_id": true, "challenge": true}) != nil || !in.Valid() {
			failure(w, 400, "INVALID_RECONCILER_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, err := s.Q.ReconciliationSnapshot(ctx, v, in)
		switch {
		case errors.Is(err, scannerauth.ErrDenied):
			failure(w, 401, "RECONCILER_AUTH_REQUIRED")
		case errors.Is(err, scanqueue.ErrContextUnbound):
			failure(w, 409, "RECONCILIATION_CONTEXT_UNBOUND")
		case err != nil:
			queueError(w, err)
		default:
			reply(w, 200, out)
		}
	case "/internal/v1/scanner/reconciler/confirm":
		var in scanevidence.CleanupConfirmationRequest
		if authorizerDecode(r, &in, map[string]bool{"job_id": true, "generation_id": true, "membership_digest": true, "engine_digest": true, "registry_namespace_digest": true, "absent": true}) != nil || !in.Valid() {
			failure(w, 400, "INVALID_RECONCILER_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, err := s.Q.ConfirmCleanup(ctx, v, in)
		switch {
		case errors.Is(err, scannerauth.ErrDenied):
			failure(w, 401, "RECONCILER_AUTH_REQUIRED")
		case errors.Is(err, scanqueue.ErrContextUnbound):
			failure(w, 409, "RECONCILIATION_CONTEXT_UNBOUND")
		case errors.Is(err, scanqueue.ErrConflict):
			failure(w, 409, "CLEANUP_NOT_RELEASABLE")
		case err != nil:
			queueError(w, err)
		default:
			reply(w, 200, out)
		}
	case "/internal/v1/scanner/reconciler/repair":
		var in scanevidence.MutationRepairRequest
		if authorizerDecode(r, &in, map[string]bool{"job_id": true, "generation_id": true, "membership_digest": true, "engine_digest": true, "registry_namespace_digest": true, "fence": true, "resolutions": true}) != nil || !in.Valid() || !canonicalRepair(in) {
			failure(w, 400, "INVALID_RECONCILER_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, err := s.Q.RepairMutations(ctx, v, in)
		switch {
		case errors.Is(err, scannerauth.ErrDenied):
			failure(w, 401, "RECONCILER_AUTH_REQUIRED")
		case errors.Is(err, scanqueue.ErrContextUnbound):
			failure(w, 409, "RECONCILIATION_CONTEXT_UNBOUND")
		case errors.Is(err, scanqueue.ErrConflict):
			failure(w, 409, "MUTATION_NOT_REPAIRABLE")
		case err != nil:
			queueError(w, err)
		default:
			reply(w, 200, out)
		}
	default:
		failure(w, 404, "RECONCILER_OPERATION_UNAVAILABLE")
	}
}

func ProbeReconciler(ctx context.Context, socket, credential string) (scanevidence.ReconcilerIdentity, error) {
	b, err := identityBytes(ctx, socket, credential, "reconciler/identity")
	if err != nil {
		return scanevidence.ReconcilerIdentity{}, err
	}
	var v scanevidence.ReconcilerIdentity
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return v, fmt.Errorf("invalid reconciler identity response")
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(bytes.TrimSpace(b), canonical) || !v.Valid(time.Now()) {
		return scanevidence.ReconcilerIdentity{}, fmt.Errorf("reconciler identity binding rejected")
	}
	return v, nil
}

// canonicalRepair refuses omitted nested objects, which decode to zero values
// that a flat key check cannot see. Unknown nested fields fail auth.Decode.
func canonicalRepair(in scanevidence.MutationRepairRequest) bool {
	for _, x := range in.Resolutions {
		if x == (scanevidence.MutationResolution{}) {
			return false
		}
	}
	return in.Fence != (scanevidence.RepairFence{})
}
