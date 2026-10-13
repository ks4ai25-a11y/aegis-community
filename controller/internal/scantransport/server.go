// SPDX-License-Identifier: Apache-2.0
// Package scantransport serves an authenticated finite worker API on a private
// Unix socket. It must never be mounted on the browser-facing HTTP listener.
package scantransport

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

type Server struct {
	Q    *scanqueue.Queue
	Auth *scannerauth.Registry
}
type LeaseRequest struct {
	Job    string `json:"job_id"`
	Digest string `json:"request_digest"`
	Token  string `json:"lease_token"`
	Code   string `json:"error_code,omitempty"`
}

var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var jobPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}
func failure(w http.ResponseWriter, status int, code string) {
	reply(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func (s *Server) Handler() http.Handler {
	slots := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			failure(w, 429, "WORKER_BUSY")
			return
		}
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Origin")) > 0 || len(r.Header.Values("Cookie")) > 0 {
			failure(w, 403, "WORKER_CHANNEL_REQUIRED")
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") || !tokenPattern.MatchString(strings.TrimPrefix(headers[0], "Bearer ")) {
			failure(w, 401, "WORKER_AUTH_REQUIRED")
			return
		}
		worker, e := s.Auth.Authenticate(strings.TrimPrefix(headers[0], "Bearer "))
		if e != nil {
			failure(w, 401, "WORKER_AUTH_REQUIRED")
			return
		}
		path := r.URL.Path
		switch path {
		case "/internal/v1/scanner/workspace":
			s.workspace(w, r, worker)
		case "/internal/v1/scanner/launch":
			s.launch(w, r, worker)
		case "/internal/v1/scanner/receipt":
			s.receipt(w, r, worker)
		case "/internal/v1/scanner/identity", "/internal/v1/scanner/claim":
			if decode(r, &struct{}{}, nil) != nil {
				failure(w, 400, "INVALID_WORKER_REQUEST")
				return
			}
			if path == "/internal/v1/scanner/identity" {
				reply(w, 200, worker)
				return
			}
			lease, e := s.Q.Claim(worker.ID, worker.Owner)
			if e == sql.ErrNoRows {
				reply(w, 204, nil)
				return
			}
			if e != nil {
				queueError(w, e)
				return
			}
			// Explicit private wire DTO: only this enrolled channel receives the lease
			// capability. General Lease serialization deliberately omits it.
			reply(w, 200, map[string]any{"schema_version": "1.0", "launch_protocol": "1.0", "workspace_protocol": "1.0", "guard_set": lease.Guards, "job": lease.Job, "application_map": lease.Map, "lease_token": lease.Token, "deadline": lease.Deadline})
		case "/internal/v1/scanner/guard", "/internal/v1/scanner/fail", "/internal/v1/scanner/finish":
			var in LeaseRequest
			keys := map[string]bool{"job_id": true, "request_digest": true, "lease_token": true}
			if path == "/internal/v1/scanner/fail" {
				keys["error_code"] = true
			}
			if decode(r, &in, keys) != nil || !jobPattern.MatchString(in.Job) || !hashPattern.MatchString(in.Digest) || !tokenPattern.MatchString(in.Token) {
				failure(w, 400, "INVALID_WORKER_REQUEST")
				return
			}
			j, e := s.Q.Get(worker.Owner, in.Job)
			if e != nil {
				queueError(w, e)
				return
			}
			if j.RequestDigest != in.Digest {
				failure(w, 409, "SCAN_IDENTITY_CONFLICT")
				return
			}
			l := scanqueue.Lease{Job: j, Worker: worker.ID, Token: in.Token}
			if path == "/internal/v1/scanner/finish" {
				result, e := s.Q.Finalize(l)
				if e != nil {
					queueError(w, e)
					return
				}
				reply(w, 200, result)
				return
			}
			if path == "/internal/v1/scanner/guard" {
				e = s.Q.Guard(l)
			} else {
				e = s.Q.Fail(l, in.Code)
			}
			if e != nil {
				queueError(w, e)
				return
			}
			if path == "/internal/v1/scanner/guard" {
				reply(w, 200, map[string]string{"state": "running"})
			} else {
				reply(w, 200, map[string]any{"state": "tool_error", "cleanup_required": true})
			}
		default:
			failure(w, 404, "WORKER_OPERATION_UNAVAILABLE")
		}
	})
}

// Canonical flat key validation also rejects Go case-fold aliases. auth.Decode
// supplies duplicate-key, nesting, unknown-field and trailing-data rejection.
func decode(r *http.Request, out any, keys map[string]bool) error {
	b, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, 8192))
	if e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return errors.New("invalid worker object")
	}
	for key, value := range fields {
		if !keys[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("unknown worker field")
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return auth.Decode(r, out)
}
func queueError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, sql.ErrNoRows):
		failure(w, 404, "SCAN_UNAVAILABLE")
	case errors.Is(e, scanqueue.ErrLease):
		failure(w, 403, "WORKER_LEASE_UNAVAILABLE")
	case errors.Is(e, scanqueue.ErrCleanup):
		failure(w, 409, "SCAN_ADMISSION_OCCUPIED")
	case errors.Is(e, scanqueue.ErrConflict):
		failure(w, 409, "SCAN_IDENTITY_CONFLICT")
	case errors.Is(e, scanqueue.ErrFull):
		failure(w, 429, "SCANNER_STORAGE_FULL")
	case errors.Is(e, scanqueue.ErrInput):
		failure(w, 400, "INVALID_WORKER_REQUEST")
	default:
		failure(w, 503, "WORKER_STATE_UNAVAILABLE")
	}
}
