// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"time"
)

// Probe is a local diagnostic. Credentials are read from a private file, never
// argv, owner cookies, query strings, logs or arbitrary TCP destinations.
func identityBytes(ctx context.Context, socket, credential, operation string) ([]byte, error) {
	if operation != "identity" && operation != "verifier/identity" && operation != "authorizer/identity" {
		return nil, fmt.Errorf("unsupported identity operation")
	}
	if operation != "identity" && validateVerifierParent(credential) != nil {
		return nil, fmt.Errorf("private verifier credential parent required")
	}
	f, e := openCredential(credential)
	if e != nil {
		return nil, fmt.Errorf("private worker credential unavailable")
	}
	defer f.Close()
	token, e := io.ReadAll(io.LimitReader(f, 66))
	if e != nil || len(token) != 65 || token[64] != '\n' || !tokenPattern.Match(token[:64]) {
		return nil, fmt.Errorf("invalid private worker credential")
	}
	if validateSocket(socket) != nil {
		return nil, fmt.Errorf("explicit Unix socket required")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if validateSocket(socket) != nil {
			return nil, fmt.Errorf("private socket identity unavailable")
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, "POST", "http://unix/internal/v1/scanner/"+operation, bytes.NewReader([]byte("{}")))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token[:64]))
	response, e := client.Do(request)
	if e != nil {
		return nil, fmt.Errorf("private worker channel unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("worker probe rejected with HTTP %d", response.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(b) > 8192 {
		return nil, fmt.Errorf("worker response exceeds budget")
	}
	return b, nil
}
func Probe(ctx context.Context, socket, credential string) (scannerauth.Worker, error) {
	b, e := identityBytes(ctx, socket, credential, "identity")
	if e != nil {
		return scannerauth.Worker{}, e
	}
	var worker scannerauth.Worker
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&worker) != nil || worker.ID == "" || worker.Owner == "" || worker.State != "active" {
		return worker, fmt.Errorf("invalid worker identity response")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return worker, fmt.Errorf("trailing worker identity response")
	}
	return worker, nil
}

func ProbeVerifier(ctx context.Context, socket, credential string) (scanevidence.VerifierIdentity, error) {
	b, e := identityBytes(ctx, socket, credential, "verifier/identity")
	if e != nil {
		return scanevidence.VerifierIdentity{}, e
	}
	var v scanevidence.VerifierIdentity
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) != nil {
		return scanevidence.VerifierIdentity{}, fmt.Errorf("invalid verifier identity response")
	}
	canonical, e := json.Marshal(v)
	if e != nil || !bytes.Equal(bytes.TrimSpace(b), canonical) || scanevidence.ValidateVerifierIdentity(v, v.Owner, v.ID, v.Engine, v.Registry, time.Now()) != nil {
		return scanevidence.VerifierIdentity{}, fmt.Errorf("verifier identity binding rejected")
	}
	return v, nil
}
