// SPDX-License-Identifier: Apache-2.0
// Package detect implements the bounded deterministic behavioural detectors of
// the v4 catalogue (E4). Detectors only record incidents: none blocks traffic,
// and none relies on a model. Thresholds are explicit, versioned knobs.
package detect

import (
	"aegis.local/controller/internal/domain"
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "1.0"

// Knobs are the reproducible thresholds. Defaults favour few false positives.
type Knobs struct {
	EnumerationWindow   time.Duration // DET-02
	EnumerationDistinct int
	BruteWindow         time.Duration // DET-03
	BruteFailures       int
	BurstWindow         time.Duration // DET-04
	BurstRequests       int
	ErrorWindow         time.Duration // DET-05
	ErrorCount          int
	ErrorRatioPercent   int
	MaxKeys             int
}

func Defaults() Knobs {
	return Knobs{
		EnumerationWindow: time.Minute, EnumerationDistinct: 30,
		BruteWindow: 5 * time.Minute, BruteFailures: 10,
		BurstWindow: 10 * time.Second, BurstRequests: 200,
		ErrorWindow: time.Minute, ErrorCount: 20, ErrorRatioPercent: 50,
		MaxKeys: 4096,
	}
}

// Signal is one detector firing. Key is a pseudonymous client or site key;
// Evidence lists retained event IDs that crossed the threshold.
type Signal struct {
	Detector   string
	Site       string
	Key        string
	Bucket     int64
	Summary    string
	Severity   string
	Confidence string
	Evidence   []string
	Window     time.Duration
	Threshold  int
	Observed   int
	Assumption string
}

type sample struct {
	at    time.Time
	event string
	value string
	flag  bool
}

// window keeps at most cap samples newer than span; it is the bounded ring
// from the E4.1 pseudocode.
type window struct {
	samples []sample
	fired   map[string]int64
}

func (w *window) add(s sample, span time.Duration, limit int) {
	cut := s.at.Add(-span)
	i := 0
	for i < len(w.samples) && w.samples[i].at.Before(cut) {
		i++
	}
	w.samples = append(w.samples[i:], s)
	if len(w.samples) > limit {
		w.samples = w.samples[len(w.samples)-limit:]
	}
}

func (w *window) evidence(n int) []string {
	out := []string{}
	for i := len(w.samples) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, w.samples[i].event)
	}
	return out
}

type Engine struct {
	K       Knobs
	mu      sync.Mutex
	keys    map[string]*list.Element
	order   *list.List
	Evicted atomic.Uint64
}

type entry struct {
	key string
	w   *window
}

func New(k Knobs) *Engine {
	return &Engine{K: k, keys: map[string]*list.Element{}, order: list.New()}
}

// get returns the window for key, evicting the least recently used window when
// the cardinality cap is reached. Eviction is signal loss, never evidence of safety.
func (e *Engine) get(key string) *window {
	if el, ok := e.keys[key]; ok {
		e.order.MoveToFront(el)
		return el.Value.(*entry).w
	}
	if e.order.Len() >= e.K.MaxKeys {
		last := e.order.Back()
		delete(e.keys, last.Value.(*entry).key)
		e.order.Remove(last)
		e.Evicted.Add(1)
	}
	w := &window{fired: map[string]int64{}}
	e.keys[key] = e.order.PushFront(&entry{key, w})
	return w
}

// fire returns true once per detector, key and window bucket (the cooldown).
func (w *window) fire(detector string, bucket int64) bool {
	if w.fired[detector] == bucket {
		return false
	}
	w.fired[detector] = bucket
	return true
}

func bucket(at time.Time, span time.Duration) int64 { return at.UnixNano() / int64(span) }

// Observe feeds one persisted event and returns any signals it completes.
func (e *Engine) Observe(ev domain.Event) []Signal {
	if ev.Source != "caddy-access" || ev.Status == nil {
		return nil
	}
	at, err := time.Parse(time.RFC3339Nano, ev.At)
	if err != nil {
		return nil
	}
	status := *ev.Status
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Signal
	if ev.ClientKey != "" {
		client := ev.Site + "|" + ev.ClientKey
		// DET-02: many distinct raw paths, mostly unsuccessful, from one client.
		w := e.get("enum|" + client)
		w.add(sample{at, ev.ID, ev.PathKey, status >= 400}, e.K.EnumerationWindow, 512)
		distinct, failed := map[string]bool{}, 0
		for _, s := range w.samples {
			if s.value != "" {
				distinct[s.value] = true
			}
			if s.flag {
				failed++
			}
		}
		if len(distinct) >= e.K.EnumerationDistinct && failed*2 >= len(w.samples) {
			if b := bucket(at, e.K.EnumerationWindow); w.fire("DET-02", b) {
				out = append(out, Signal{"DET-02", ev.Site, ev.ClientKey, b, "Path enumeration candidate on " + ev.Site, "low", "medium", w.evidence(20), e.K.EnumerationWindow, e.K.EnumerationDistinct, len(distinct), "One pseudonymous client requested many distinct paths, most unsuccessfully. Crawlers, shared NAT and deploy checks can look similar."})
			}
		}
		// DET-03: repeated 401/403 responses to one client.
		if status == 401 || status == 403 {
			w := e.get("brute|" + client)
			w.add(sample{at: at, event: ev.ID}, e.K.BruteWindow, 256)
			if len(w.samples) >= e.K.BruteFailures {
				if b := bucket(at, e.K.BruteWindow); w.fire("DET-03", b) {
					out = append(out, Signal{"DET-03", ev.Site, ev.ClientKey, b, "Repeated authentication or authorization failures on " + ev.Site, "medium", "medium", w.evidence(20), e.K.BruteWindow, e.K.BruteFailures, len(w.samples), "Counts application 401/403 responses only; it cannot see account lockout, and a shared address may represent several users."})
				}
			}
		}
		// DET-04: request burst from one client (advisory; no automatic 429).
		w = e.get("burst|" + client)
		w.add(sample{at: at, event: ev.ID}, e.K.BurstWindow, e.K.BurstRequests+1)
		if len(w.samples) >= e.K.BurstRequests {
			if b := bucket(at, e.K.BurstWindow); w.fire("DET-04", b) {
				out = append(out, Signal{"DET-04", ev.Site, ev.ClientKey, b, "Request burst from one client on " + ev.Site, "low", "high", w.evidence(20), e.K.BurstWindow, e.K.BurstRequests, len(w.samples), "Advisory only. Legitimate promotions, load tests and batch clients can exceed this rate; no request was rate limited."})
			}
		}
	}
	// DET-05: site-wide 5xx spike as a share of all responses.
	w := e.get("errors|" + ev.Site)
	w.add(sample{at: at, event: ev.ID, flag: status >= 500}, e.K.ErrorWindow, 2048)
	errors := 0
	for _, s := range w.samples {
		if s.flag {
			errors++
		}
	}
	if status >= 500 && errors >= e.K.ErrorCount && errors*100 >= e.K.ErrorRatioPercent*len(w.samples) {
		if b := bucket(at, e.K.ErrorWindow); w.fire("DET-05", b) {
			ev5 := []string{}
			for i := len(w.samples) - 1; i >= 0 && len(ev5) < 20; i-- {
				if w.samples[i].flag {
					ev5 = append(ev5, w.samples[i].event)
				}
			}
			out = append(out, Signal{"DET-05", ev.Site, ev.Site, b, "Server error spike on " + ev.Site, "medium", "high", ev5, e.K.ErrorWindow, e.K.ErrorCount, errors, "Upstream deploys and outages also produce 5xx spikes; correlate with probing before treating this as attack impact."})
		}
	}
	// DET-06: a successful response from a sensitive-looking route.
	if status < 400 && sensitive(ev.Route) {
		out = append(out, Signal{"DET-06", ev.Site, ev.Method + " " + ev.Route, 0, "Sensitive-looking route answered on " + ev.Site + ": " + ev.Method + " " + ev.Route, "info", "high", []string{ev.ID}, 0, 1, 1, "Route names suggest administrative or diagnostic functions. This is not evidence of a vulnerability or missing authorization."})
	}
	return out
}

var sensitiveSegments = map[string]bool{"admin": true, "debug": true, "internal": true, "actuator": true, ".env": true}

func sensitive(route string) bool {
	for _, s := range strings.Split(route, "/") {
		if sensitiveSegments[s] {
			return true
		}
	}
	return false
}
