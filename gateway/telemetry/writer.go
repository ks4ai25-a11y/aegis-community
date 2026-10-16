// SPDX-License-Identifier: Apache-2.0
// Package telemetry sanitizes pinned Caddy/Coraza log records before any write.
package telemetry

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// pseudonyms turn client addresses and raw paths into short keyed digests so
// detectors can count distinct clients and paths without storing either. The key
// is random, held only in memory and replaced every UTC day; digests cannot be
// linked across days or restarts and cannot be reversed without the key.
var pseudonyms struct {
	mu  sync.Mutex
	day int64
	key [32]byte
}

func pseudonym(kind, value string) string {
	day := time.Now().UTC().Unix() / 86400
	pseudonyms.mu.Lock()
	if pseudonyms.day != day {
		if _, e := rand.Read(pseudonyms.key[:]); e != nil {
			pseudonyms.mu.Unlock()
			return ""
		}
		pseudonyms.day = day
	}
	mac := hmac.New(sha256.New, pseudonyms.key[:])
	pseudonyms.mu.Unlock()
	mac.Write([]byte(kind + "\x00" + value))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

var ruleID = regexp.MustCompile(`\[id "([0-9]{1,7})"\]`)
var txID = regexp.MustCompile(`\[unique_id "([A-Za-z0-9_.-]{1,128})"\]`)

// target keeps only the name of a matched request argument (never its value), so an
// owner can scope an exclusion to exactly that parameter.
var target = regexp.MustCompile(`found within ARGS(?:_GET|_POST)?:([a-zA-Z][a-zA-Z0-9_]{0,31})(?:[^a-zA-Z0-9_]|$)`)
var numberSegment = regexp.MustCompile(`^[0-9]+$|^[0-9a-fA-F-]{20,}$`)

// Route is analytics-only and deliberately omits unrecognized segments.
func Route(raw string) string {
	raw = strings.SplitN(raw, "?", 2)[0]
	if len(raw) > 2048 {
		return "/{redacted}"
	}
	segments := strings.Split(raw, "/")
	if len(segments) > 16 {
		return "/{redacted}"
	}
	known := map[string]bool{"": true, "healthz": true, "catalog": true, "test-pattern": true, "api": true, "users": true, "orders": true, "products": true, "admin": true, "login": true, ".env": true, "debug": true, "internal": true, "actuator": true, "events": true}
	for i, s := range segments {
		if numberSegment.MatchString(s) {
			segments[i] = "{id}"
		} else if !known[s] {
			segments[i] = "{segment}"
		}
	}
	return strings.Join(segments, "/")
}

type Writer struct {
	Path  string `json:"path"`
	queue chan []byte
	done  chan struct{}
	drops atomic.Uint64
	file  *os.File
	mu    sync.Mutex
}

func init() { caddy.RegisterModule(Writer{}) }
func (Writer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.logging.writers.aegis", New: func() caddy.Module { return new(Writer) }}
}
func (w *Writer) Provision(caddy.Context) error {
	if w.Path == "" || !filepath.IsAbs(w.Path) {
		return fmt.Errorf("absolute telemetry path required")
	}
	return nil
}
func (w *Writer) String() string    { return "aegis:" + w.Path }
func (w *Writer) WriterKey() string { return w.String() }
func (w *Writer) OpenWriter() (io.WriteCloser, error) {
	f, e := os.OpenFile(w.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	w.file = f
	w.queue = make(chan []byte, 2048)
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		for b := range w.queue {
			if st, e := w.file.Stat(); e == nil && st.Size() > 16<<20 {
				w.file.Close()
				os.Remove(w.Path + ".1")
				os.Rename(w.Path, w.Path+".1")
				w.file, _ = os.OpenFile(w.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			}
			if w.file == nil {
				// Reopen after rotation failed; the record is lost and must be counted.
				w.file, _ = os.OpenFile(w.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			}
			if w.file == nil {
				w.drops.Add(1)
			} else if _, e := w.file.Write(b); e != nil {
				w.drops.Add(1)
			}
		}
		if w.file != nil {
			w.file.Close()
		}
	}()
	return w, nil
}
func (w *Writer) Write(b []byte) (int, error) {
	// Raw bytes never enter the asynchronous queue.
	safe := Sanitize(b)
	if safe == nil {
		return len(b), nil
	}
	safe["dropped_before"] = w.drops.Load()
	out, e := json.Marshal(safe)
	if e != nil {
		return len(b), nil
	}
	out = append(out, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.queue == nil {
		return len(b), nil
	}
	select {
	case w.queue <- out:
	default:
		w.drops.Add(1)
	}
	return len(b), nil
}
func (w *Writer) Close() error {
	w.mu.Lock()
	q := w.queue
	w.queue = nil
	if q != nil {
		close(q)
	}
	w.mu.Unlock()
	if q != nil {
		<-w.done
	}
	return nil
}
func Sanitize(b []byte) map[string]any {
	if len(b) > 128<<10 {
		return nil
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	var logger, msg string
	json.Unmarshal(raw["logger"], &logger)
	json.Unmarshal(raw["msg"], &msg)
	out := map[string]any{"source_schema": "caddy-2.11.4-coraza-2.6.2", "source": "coraza", "collection_status": "complete", "privacy_version": "1.0"}
	var ts float64
	json.Unmarshal(raw["ts"], &ts)
	out["ts"] = ts
	if strings.HasPrefix(logger, "http.log.access") {
		var req struct {
			Method   string              `json:"method"`
			URI      string              `json:"uri"`
			ClientIP string              `json:"client_ip"`
			RemoteIP string              `json:"remote_ip"`
			Headers  map[string][]string `json:"headers"`
		}
		if json.Unmarshal(raw["request"], &req) != nil {
			return nil
		}
		var status int
		json.Unmarshal(raw["status"], &status)
		out["source"] = "caddy-access"
		out["method"] = req.Method
		out["route_template"] = Route(req.URI)
		client := req.ClientIP
		if client == "" {
			client = req.RemoteIP
		}
		if client != "" {
			if k := pseudonym("client", client); k != "" {
				out["client_key"] = k
			}
		}
		if path := strings.SplitN(req.URI, "?", 2)[0]; path != "" && len(path) <= 2048 {
			if k := pseudonym("path", path); k != "" {
				out["path_key"] = k
			}
		}
		out["http_status"] = status
		var headers map[string][]string
		json.Unmarshal(raw["resp_headers"], &headers)
		for k, v := range headers {
			if len(v) == 0 {
				continue
			}
			switch strings.ToLower(k) {
			case "x-aegis-request-id":
				out["request_id"] = v[0]
			case "x-aegis-revision":
				out["gateway_revision"] = v[0]
			case "x-aegis-mode":
				out["mode"] = v[0]
			}
		}
		return out
	}
	if strings.Contains(logger, "waf") {
		ids := ruleID.FindStringSubmatch(msg)
		tx := txID.FindStringSubmatch(msg)
		if len(ids) == 2 && len(tx) == 2 {
			out["rule_id"] = ids[1]
			out["request_id"] = tx[1]
			if t := target.FindStringSubmatch(msg); len(t) == 2 {
				out["target"] = "ARGS:" + t[1]
			}
			return out
		}
		if msg == "WAF rule violation detected" {
			var id string
			json.Unmarshal(raw["unique_id"], &id)
			if txID.MatchString(`[unique_id "` + id + `"]`) {
				out["request_id"] = id
				out["interrupted"] = true
				return out
			}
		}
	}
	return nil
}

func (w *Writer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		if d.Val() != "path" || !d.NextArg() {
			return d.Err("expected path")
		}
		w.Path = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}
