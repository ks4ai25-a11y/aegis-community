// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Authorizer mutations require the separately selected immutable binding and
// durable generation. Existing observer/worker credentials never gain this role.
func (s *Server) authorizer(w http.ResponseWriter, r *http.Request, token string) {
	if len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
		failure(w, 400, "INVALID_AUTHORIZER_REQUEST")
		return
	}
	v, e := s.Auth.AuthenticateAuthorizer(token)
	if e != nil {
		failure(w, 401, "AUTHORIZER_AUTH_REQUIRED")
		return
	}
	switch r.URL.Path {
	case "/internal/v1/scanner/authorizer/identity", "/internal/v1/scanner/authorizer/binding":
		if authorizerDecode(r, &struct{}{}, nil) != nil {
			failure(w, 400, "INVALID_AUTHORIZER_REQUEST")
			return
		}
		if r.URL.Path == "/internal/v1/scanner/authorizer/identity" {
			reply(w, 200, v)
			return
		}
		out, e := s.Q.MutationBindingForAuthorizer(r.Context(), v)
		if e != nil {
			queueError(w, e)
			return
		}
		reply(w, 200, out)
	case "/internal/v1/scanner/authorizer/launch":
		var in scanevidence.AuthorizerLaunchRequest
		if authorizerDecode(r, &in, map[string]bool{"container_name": true, "challenge": true, "operation": true}) != nil || !in.Valid() {
			failure(w, 400, "INVALID_AUTHORIZER_REQUEST")
			return
		}
		out, e := s.Q.AuthorizerLaunch(r.Context(), v, in)
		if e != nil {
			queueError(w, e)
			return
		}
		reply(w, 200, out)
	case "/internal/v1/scanner/authorizer/admit":
		var in scanevidence.MutationRequest
		if authorizerDecode(r, &in, map[string]bool{"generation_id": true, "job_id": true, "tool_id": true, "operation": true, "launch_digest": true, "descriptor_digest": true, "target_engine_id": true}) != nil || !in.Valid() {
			failure(w, 400, "INVALID_AUTHORIZER_REQUEST")
			return
		}
		out, e := s.Q.AdmitMutation(r.Context(), v, in)
		if e != nil {
			queueError(w, e)
			return
		}
		reply(w, 200, out)
	case "/internal/v1/scanner/authorizer/complete":
		var in scanevidence.MutationCompletion
		if authorizerDecode(r, &in, map[string]bool{"intent_id": true, "generation_id": true, "response_status": true, "engine_id": true, "response_digest": true}) != nil || !in.Valid() {
			failure(w, 400, "INVALID_AUTHORIZER_REQUEST")
			return
		}
		out, e := s.Q.CompleteMutation(r.Context(), v, in)
		if e != nil {
			queueError(w, e)
			return
		}
		reply(w, 200, out)
	default:
		failure(w, 404, "AUTHORIZER_OPERATION_UNAVAILABLE")
	}
}

// Require the complete flat request shape as well as auth.Decode's duplicate,
// alias, null and trailing-data rejection. No identity-only role is elevated by
// a browser cookie or by substituting another channel's credential.
func authorizerDecode(r *http.Request, out any, keys map[string]bool) error {
	b, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, 8192))
	if e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil || len(fields) != len(keys) {
		return fmt.Errorf("invalid authorizer object")
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return decode(r, out, keys)
}

func ProbeAuthorizer(ctx context.Context, socket, credential string) (scanevidence.AuthorizerIdentity, error) {
	b, e := identityBytes(ctx, socket, credential, "authorizer/identity")
	if e != nil {
		return scanevidence.AuthorizerIdentity{}, e
	}
	var v scanevidence.AuthorizerIdentity
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) != nil {
		return v, fmt.Errorf("invalid authorizer identity response")
	}
	canonical, e := json.Marshal(v)
	if e != nil || !bytes.Equal(bytes.TrimSpace(b), canonical) || scanevidence.ValidateAuthorizerIdentity(v, v.Owner, v.ID, v.Engine, v.Registry, v.Policy, time.Now()) != nil {
		return scanevidence.AuthorizerIdentity{}, fmt.Errorf("authorizer identity binding rejected")
	}
	return v, nil
}
