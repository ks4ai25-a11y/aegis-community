// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"net/http"
	"strings"
	"time"

	"aegis.local/controller/internal/connector"
)

// DesktopTransportHandler is served only by the separate mutually authenticated listener.
func (s *Server) DesktopTransportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !trustedDesktopPeer(r, time.Now()) {
			fail(w, http.StatusForbidden, "DESKTOP_PEER_REQUIRED", "A verified desktop client certificate is required")
			return
		}
		path, ok := strings.CutPrefix(r.URL.Path, "/api/v1")
		if !ok || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.RawQuery != "" ||
			len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Origin")) != 0 {
			fail(w, http.StatusForbidden, "DESKTOP_TRANSPORT_DENIED", "This listener accepts only direct desktop bridge requests")
			return
		}
		if r.Method == http.MethodPost && (path == "/desktop/pairing/claim" || path == "/desktop/pairing/redeem") {
			if len(r.Header.Values("Authorization")) == 0 {
				s.api(w, r)
				return
			}
		} else if path == "/desktop/renew" && r.Method == http.MethodPost ||
			strings.HasPrefix(path, "/desktop/") && connector.Allowed(r.Method, path) {
			if h := r.Header.Values("Authorization"); len(h) == 1 && strings.HasPrefix(h[0], "Bearer "+connector.PairedPrefix) {
				s.api(w, r)
				return
			}
		}
		fail(w, http.StatusForbidden, "DESKTOP_TRANSPORT_DENIED", "Route or credential is unavailable on the desktop listener")
	})
}

func trustedDesktopPeer(r *http.Request, now time.Time) bool {
	if r.TLS == nil {
		return false
	}
	for _, chain := range r.TLS.VerifiedChains {
		valid := len(chain) != 0
		for _, cert := range chain {
			valid = valid && !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
		}
		if valid {
			return true
		}
	}
	return false
}
