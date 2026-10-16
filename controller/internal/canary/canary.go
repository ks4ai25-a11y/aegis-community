// SPDX-License-Identifier: Apache-2.0
// Package canary implements DET-07: it sends the bundled synthetic benign and
// negative controls through the live gateway (demo host only) and checks that the
// active revision still produces the expected outcome. A failure records an
// urgent incident and recommends rollback; it never changes policy itself.
package canary

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/controller/internal/verify"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const DetectorVersion = "1.0"

// Marks lets ingest recognise canary traffic so detectors do not count it.
type Marks struct{ m sync.Map }

func (k *Marks) Add(id string) { k.m.Store(id, time.Now().Add(10*time.Minute)) }
func (k *Marks) Has(id string) bool {
	v, ok := k.m.Load(id)
	if !ok {
		return false
	}
	if time.Now().After(v.(time.Time)) {
		k.m.Delete(id)
		return false
	}
	return true
}

type Result struct {
	At        string `json:"checked_at"`
	Revision  string `json:"active_revision"`
	Gateway   string `json:"gateway_revision"`
	Mode      string `json:"mode"`
	Control   int    `json:"control_status"`
	Negative  int    `json:"negative_status"`
	Matched   bool   `json:"negative_rule_matched"`
	Outcome   string `json:"outcome"`
	Incident  string `json:"incident_id,omitempty"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"negative_request_id,omitempty"`
}

type Canary struct {
	S       *store.Store
	Gateway string // base URL, e.g. http://gateway:8080
	Marks   *Marks
	Client  *http.Client
	Wait    time.Duration // how long to wait for the WAF record (default 10s)
	mu      sync.Mutex
}

func (c *Canary) send(ctx context.Context, path string) (int, string, string, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", c.Gateway+path, nil)
	if e != nil {
		return 0, "", "", e
	}
	req.Host = "demo.example.test"
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, e := client.Do(req)
	if e != nil {
		return 0, "", "", e
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	id := resp.Header.Get("X-Aegis-Request-ID")
	if id != "" && c.Marks != nil {
		c.Marks.Add(id)
	}
	return resp.StatusCode, id, resp.Header.Get("X-Aegis-Revision"), nil
}

// Run performs one check and records its result (and any incident).
func (c *Canary) Run(ctx context.Context) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, digest, e := c.S.Active()
	r := Result{At: domain.Now(), Revision: digest, Mode: p.Mode}
	if e != nil {
		r.Outcome, r.Detail = "INCONCLUSIVE", "active policy unavailable"
		return c.save(r)
	}
	var control, negative int
	var rid, revision string
	if control, _, revision, e = c.send(ctx, verify.Corpus[0]); e == nil {
		negative, rid, _, e = c.send(ctx, verify.Corpus[1])
	}
	r.Control, r.Negative, r.Gateway, r.RequestID = control, negative, revision, rid
	if e != nil {
		r.Outcome, r.Detail = "INCONCLUSIVE", "gateway unreachable"
		return c.save(r)
	}
	// Wait for the WAF record of the negative control to be ingested.
	rules := []string{}
	wait := c.Wait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) && rid != "" {
		rows, e := c.S.DB.QueryContext(ctx, "SELECT document FROM events WHERE request=?", rid)
		if e == nil {
			for rows.Next() {
				var b string
				var ev domain.Event
				if rows.Scan(&b) == nil && json.Unmarshal([]byte(b), &ev) == nil {
					rules = append(rules, ev.Rules...)
				}
			}
			rows.Close()
		}
		for _, x := range rules {
			if x == "942100" {
				r.Matched = true
			}
		}
		if r.Matched {
			break
		}
		select {
		case <-ctx.Done():
			deadline = time.Now()
		case <-time.After(250 * time.Millisecond):
		}
	}
	r.Outcome = verify.Classify(control, negative, rules, p.Mode)
	if revision != digest {
		r.Outcome, r.Detail = "FAIL", "the gateway is serving a different revision than the controller recorded"
	}
	if r.Outcome == "FAIL" {
		r.Incident = c.incident(r)
	}
	return c.save(r)
}

func (c *Canary) save(r Result) Result {
	b, _ := json.Marshal(r)
	c.S.Set("canary_last", string(b))
	return r
}

// incident records one DET-07 incident per revision and hour, linked to the
// canary's own evidence, with rollback as the recommended response.
func (c *Canary) incident(r Result) string {
	bucket := time.Now().UTC().Format("2006-01-02T15")
	id := domain.Hash([]byte("DET-07|" + r.Revision + "|" + bucket))
	why := fmt.Sprintf("expected mode %s outcome, observed control %d, negative %d, CRS 942100 matched %t", r.Mode, r.Control, r.Negative, r.Matched)
	if r.Detail != "" {
		why = r.Detail
	}
	notes, _ := json.Marshal(map[string]any{"detector_id": "DET-07", "detector_version": DetectorVersion, "site_id": "site_demo", "window_seconds": 0, "threshold": 1, "observed": 1, "response": "record_only",
		"assumption": "The bundled synthetic controls no longer behave as the active revision requires (" + why + "). Verify the fixture and gateway, then consider rolling back."})
	tx, e := c.S.DB.Begin()
	if e != nil {
		return ""
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT OR IGNORE INTO incidents(id,summary,opened_at,state,severity,confidence,notes) VALUES(?,?,?,'open','high','high',?)", id, "Policy regression: live canary failed for revision "+short(r.Revision), r.At, string(notes)); e != nil {
		return ""
	}
	if r.RequestID != "" {
		tx.Exec("INSERT OR IGNORE INTO incident_events SELECT ?,id FROM events WHERE request=? LIMIT 10", id, r.RequestID)
	}
	if store.AuditTx(tx, "system", "canary.failed", id, "open", map[string]string{"revision": r.Revision, "detail": why}) != nil || tx.Commit() != nil {
		return ""
	}
	return id
}

func short(d string) string {
	if len(d) > 19 {
		return d[7:19]
	}
	return d
}

// Last returns the most recent stored result, if any.
func Last(s *store.Store) (Result, bool) {
	var r Result
	v, e := s.Get("canary_last")
	if e != nil || v == "" || json.Unmarshal([]byte(v), &r) != nil {
		return r, false
	}
	return r, true
}
