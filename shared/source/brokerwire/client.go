// SPDX-License-Identifier: Apache-2.0
package brokerwire

import (
	"aegis.local/source/privateipc"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

func Dispatch(ctx context.Context, socket, credential string) (Outcome, error) {
	token, e := privateipc.ReadToken(credential)
	if e != nil || privateipc.ValidateSocket(socket) != nil {
		return Outcome{}, ErrProtocol
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, ResponseHeaderTimeout: 16 * time.Minute, MaxResponseHeaderBytes: 8192, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if privateipc.ValidateSocket(socket) != nil {
			return nil, ErrProtocol
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 16 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, "POST", "http://unix"+RunPath, bytes.NewReader([]byte(`{}`)))
	if e != nil {
		return Outcome{}, ErrProtocol
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, e := client.Do(request)
	if e != nil {
		return Outcome{}, ErrProtocol
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/json" {
		return Outcome{}, ErrProtocol
	}
	return Decode(raw)
}
