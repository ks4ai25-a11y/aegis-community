// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Enrollment is deliberately separate from observer/worker credentials. Only
// identity is exposed until durable mutation admission is integrated.
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
	if r.URL.Path != "/internal/v1/scanner/authorizer/identity" {
		failure(w, 404, "AUTHORIZER_OPERATION_UNAVAILABLE")
		return
	}
	if decode(r, &struct{}{}, nil) != nil {
		failure(w, 400, "INVALID_AUTHORIZER_REQUEST")
		return
	}
	reply(w, 200, v)
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
