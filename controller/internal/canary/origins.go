// SPDX-License-Identifier: BUSL-1.1
package canary

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"net"
	"time"
)

// OriginResult reports whether a registered site's origin answered a TCP
// connection from the controller, which in the reference deployment shares no
// network with origins. Reachable means traffic may be able to bypass the gateway.
type OriginResult struct {
	Site      string `json:"site_id"`
	Reachable bool   `json:"reachable_without_gateway"`
	Incident  string `json:"incident_id,omitempty"`
}

// Dialer is replaceable in tests.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// CheckOrigins implements DET-08 (origin drift / bypass), record-only.
func CheckOrigins(ctx context.Context, s *store.Store, dial Dialer) []OriginResult {
	if dial == nil {
		d := &net.Dialer{Timeout: 2 * time.Second}
		dial = d.DialContext
	}
	p, _, e := s.Active()
	if e != nil {
		return nil
	}
	out := []OriginResult{}
	for _, site := range p.Sites {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := dial(c, "tcp", site.Origin)
		cancel()
		r := OriginResult{Site: site.ID, Reachable: err == nil}
		if err == nil {
			conn.Close()
			r.Incident = originIncident(s, site.ID)
		}
		out = append(out, r)
	}
	b, _ := json.Marshal(map[string]any{"checked_at": domain.Now(), "sites": out})
	s.Set("origin_exposure_last", string(b))
	return out
}

func originIncident(s *store.Store, site string) string {
	id := domain.Hash([]byte("DET-08|" + site + "|" + time.Now().UTC().Format("2006-01-02")))
	notes, _ := json.Marshal(map[string]any{"detector_id": "DET-08", "detector_version": DetectorVersion, "site_id": site, "window_seconds": 0, "threshold": 1, "observed": 1, "response": "record_only",
		"assumption": "The site's origin accepted a connection from the Aegis controller, which should not share a network with origins. Clients on that network may reach the application without passing the gateway. Put the origin only on the gateway's network and do not publish its port. Unreachable does not prove the origin is private: a port published on the host is not visible from here."})
	if _, e := s.DB.Exec("INSERT OR IGNORE INTO incidents(id,summary,opened_at,state,severity,confidence,notes) VALUES(?,?,?,'open','medium','medium',?)", id, "Origin of "+site+" is reachable without the gateway", domain.Now(), string(notes)); e != nil {
		return ""
	}
	s.Audit("system", "origin.reachable", id, site, nil)
	return id
}
