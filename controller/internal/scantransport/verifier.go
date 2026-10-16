// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"context"
	"errors"
	"net/http"
	"time"
)

func (s *Server) verifier(w http.ResponseWriter, r *http.Request, token string) {
	if len(r.Header.Values("Content-Encoding")) > 0 || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
		failure(w, 400, "INVALID_VERIFIER_REQUEST")
		return
	}
	v, e := s.Auth.AuthenticateVerifier(token)
	if e != nil {
		failure(w, 401, "VERIFIER_AUTH_REQUIRED")
		return
	}
	switch r.URL.Path {
	case "/internal/v1/scanner/verifier/identity":
		if decode(r, &struct{}{}, nil) != nil {
			failure(w, 400, "INVALID_VERIFIER_REQUEST")
			return
		}
		reply(w, 200, v)
	case "/internal/v1/scanner/verifier/live-launch":
		var in struct {
			Container string `json:"container_name"`
			Challenge string `json:"challenge"`
		}
		if decode(r, &in, map[string]bool{"container_name": true, "challenge": true}) != nil {
			failure(w, 400, "INVALID_VERIFIER_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, e := s.Q.LiveLaunch(ctx, v, in.Container, in.Challenge)
		switch {
		case errors.Is(e, scannerauth.ErrDenied):
			failure(w, 401, "VERIFIER_AUTH_REQUIRED")
		case errors.Is(e, scanqueue.ErrContextScope):
			failure(w, 404, "SCAN_UNAVAILABLE")
		case errors.Is(e, scanqueue.ErrContextUnbound):
			failure(w, 409, "LIVE_LAUNCH_UNBOUND")
		case e != nil:
			queueError(w, e)
		default:
			reply(w, 200, out)
		}
	case "/internal/v1/scanner/verifier/context":
		var in struct {
			Job string `json:"job_id"`
		}
		if decode(r, &in, map[string]bool{"job_id": true}) != nil || !jobPattern.MatchString(in.Job) {
			failure(w, 400, "INVALID_VERIFIER_REQUEST")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, e := s.Q.CleanupContext(ctx, v, in.Job)
		switch {
		case errors.Is(e, scannerauth.ErrDenied):
			failure(w, 401, "VERIFIER_AUTH_REQUIRED")
		case errors.Is(e, scanqueue.ErrContextScope):
			failure(w, 404, "SCAN_UNAVAILABLE")
		case errors.Is(e, scanqueue.ErrContextUnbound):
			failure(w, 409, "CLEANUP_CONTEXT_UNBOUND")
		case e != nil:
			queueError(w, e)
		default:
			reply(w, 200, out)
		}
	default:
		failure(w, 404, "VERIFIER_OPERATION_UNAVAILABLE")
	}
}
