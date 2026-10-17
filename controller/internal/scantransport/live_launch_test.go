//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLiveLaunchHTTPKeepsVerifierRoleAndFiniteRequestBoundary(t *testing.T) {
	s, worker, token, _, _, _ := verifierHTTPFixture(t)
	h := s.Handler()
	body := `{"container_name":"aegis-scan-` + strings.Repeat("a", 32) + `","challenge":"` + strings.Repeat("b", 32) + `"}`
	// This fixture deliberately has the older unbound launch. Authentic observer
	// enrollment must not turn it into a controller-bound execution observation.
	call(t, h, token, "verifier/live-launch", body, 409)
	call(t, h, worker, "verifier/live-launch", body, 401)
	call(t, h, "", "verifier/live-launch", body, 401)
	for _, payload := range []string{`{}`, `{"container_name":"invalid","challenge":"bad"}`, strings.Replace(body, `"challenge":`, `"Challenge":`, 1), strings.Replace(body, `"challenge":`, `"challenge":"wrong","challenge":`, 1), strings.Replace(body, `"container_name":`, `"unknown":1,"container_name":`, 1), body + ` {}`, strings.Replace(body, `"challenge":"`+strings.Repeat("b", 32)+`"`, `"challenge":null`, 1)} {
		call(t, h, token, "verifier/live-launch", payload, 400)
	}
	for _, kind := range []string{"cookie", "origin", "query", "encoded", "method"} {
		t.Run(kind, func(t *testing.T) {
			path := "http://unix/internal/v1/scanner/verifier/live-launch"
			method := "POST"
			if kind == "query" {
				path += "?x=1"
			}
			if kind == "encoded" {
				path = strings.Replace(path, "live-launch", "live%2dlaunch", 1)
			}
			if kind == "method" {
				method = "GET"
			}
			r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+token)
			if kind == "cookie" {
				r.Header.Set("Cookie", "session=fake")
			}
			if kind == "origin" {
				r.Header.Set("Origin", "https://example.invalid")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("browser/alternate channel accepted", w.Code)
			}
		})
	}
}
