// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Ingestor struct {
	S        *store.Store
	Path     string
	Dropped  atomic.Uint64
	Rejected atomic.Uint64
	Last     atomic.Int64
}
type Raw struct {
	Source      string  `json:"source"`
	Schema      string  `json:"source_schema"`
	TS          float64 `json:"ts"`
	Request     string  `json:"request_id"`
	Revision    *string `json:"gateway_revision"`
	Mode        string  `json:"mode"`
	Method      string  `json:"method"`
	Route       string  `json:"route_template"`
	Status      *int    `json:"http_status"`
	Rule        string  `json:"rule_id"`
	Interrupted bool    `json:"interrupted"`
	Dropped     uint64  `json:"dropped_before"`
	Collection  string  `json:"collection_status"`
	Privacy     string  `json:"privacy_version"`
}

func Normalize(b []byte) (domain.Event, error) {
	var r Raw
	if len(b) > 8192 {
		return domain.Event{}, fmt.Errorf("record too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&r); e != nil {
		return domain.Event{}, e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return domain.Event{}, fmt.Errorf("trailing record data")
	}
	if r.Schema != "caddy-2.11.4-coraza-2.6.2" || len(r.Request) > 128 || r.TS <= 0 || (r.Source != "coraza" && r.Source != "caddy-access") || len(r.Route) > 256 || len(r.Method) > 16 || len(r.Rule) > 10 || len(r.Collection) > 32 || len(r.Privacy) > 32 || len(r.Mode) > 16 || (r.Revision != nil && len(*r.Revision) > 80) {
		return domain.Event{}, fmt.Errorf("invalid source record")
	}
	at := time.Unix(0, int64(r.TS*1e9)).UTC()
	if at.After(time.Now().Add(time.Minute)) {
		return domain.Event{}, fmt.Errorf("future record")
	}
	ev := domain.Event{ID: domain.ID(), Schema: "1.0", At: at.Format(time.RFC3339Nano), Site: "site_demo", Request: r.Request, Revision: r.Revision, Type: "access", Decision: "unknown", Method: r.Method, Route: r.Route, Status: r.Status, Rules: []string{}, Collection: r.Collection, Privacy: r.Privacy, Source: r.Source, Dropped: r.Dropped, Synthetic: true}
	if r.Source == "coraza" {
		ev.Type = "waf_match"
		if r.Rule != "" {
			if _, e := strconv.Atoi(r.Rule); e != nil {
				return ev, e
			}
			ev.Rules = append(ev.Rules, r.Rule)
		}
		if r.Interrupted {
			ev.Type = "waf_interruption"
			ev.Decision = "blocked_waf"
		}
	}
	if r.Source == "caddy-access" && r.Status != nil {
		if *r.Status >= 500 {
			ev.Decision = "upstream_error"
		} else if *r.Status == 413 || *r.Status == 431 || *r.Status == 421 {
			ev.Decision = "rejected_parse"
		} else if *r.Status < 400 {
			ev.Decision = "allowed"
		}
		if r.Mode == "observe" && ev.Decision == "allowed" {
			ev.Decision = "observed"
		}
	}
	return ev, nil
}
func (i *Ingestor) Run(ctx context.Context) {
	if value, e := i.S.Get("events_dropped_total"); e == nil {
		n, _ := strconv.ParseUint(value, 10, 64)
		i.Dropped.Store(n)
	}
	if value, e := i.S.Get("ingest_rejected_total"); e == nil {
		n, _ := strconv.ParseUint(value, 10, 64)
		i.Rejected.Store(n)
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			i.read()
		}
	}
}
func (i *Ingestor) read() {
	for _, path := range []string{i.Path + ".1", i.Path} {
		f, e := os.Open(path)
		if e != nil {
			continue
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			continue
		}
		source := fmt.Sprintf("%s:%v", filepath.Base(path), st.Sys()) // inode identity is replaced below by stable platform-neutral modification/size fallback.
		// A rotated file keeps its inode. Use stat identity helper on Unix.
		source = FileIdentity(path, st)
		var off int64
		i.S.DB.QueryRow("SELECT offset FROM cursors WHERE source=?", source).Scan(&off)
		if st.Size() < off {
			off = 0
		}
		f.Seek(off, 0)
		reader := bufio.NewReaderSize(f, 8193)
		for n := 0; n < 512; n++ {
			line, consumed, tooLarge, e := boundedLine(reader)
			if e != nil {
				break
			}
			start := off
			off += consumed
			if tooLarge {
				i.Rejected.Add(1)
				continue
			}
			ev, e := Normalize(line)
			if e != nil {
				i.Rejected.Add(1)
				continue
			}
			if e = i.persist(ev, source+":"+strconv.FormatInt(start, 10)); e != nil {
				i.Dropped.Add(1)
			} else {
				i.Last.Store(time.Now().Unix())
			}
		}
		i.S.DB.Exec("INSERT INTO cursors VALUES(?,?) ON CONFLICT(source) DO UPDATE SET offset=excluded.offset", source, off)
		f.Close()
	}
	i.S.Set("events_dropped_total", strconv.FormatUint(i.Dropped.Load(), 10))
	i.S.Set("ingest_rejected_total", strconv.FormatUint(i.Rejected.Load(), 10))
	i.S.DB.Exec("DELETE FROM cursors WHERE source NOT IN (SELECT source FROM cursors ORDER BY rowid DESC LIMIT 16)")
}
func (i *Ingestor) persist(ev domain.Event, key string) error {
	st, e := os.Stat(i.S.Path)
	if e != nil {
		return e
	}
	size := st.Size()
	if wal, e := os.Stat(i.S.Path + "-wal"); e == nil {
		size += wal.Size()
	}
	if size > 256<<20 {
		return fmt.Errorf("database cap reached")
	}
	tx, e := i.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	b, _ := json.Marshal(ev)
	res, e := tx.Exec("INSERT OR IGNORE INTO events(id,at,request,source_key,document) VALUES(?,?,?,?,?)", ev.ID, ev.At, ev.Request, key, string(b))
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n > 0 && ev.Type == "waf_match" && len(ev.Rules) > 0 {
		// Actual match observations are grouped by the rule and minute, with no exploit claim.
		incident := domain.Hash([]byte(ev.At[:16] + ":" + ev.Rules[0]))
		_, e = tx.Exec("INSERT OR IGNORE INTO incidents(id,summary,opened_at,state,severity,confidence) VALUES(?,?,?,'open','medium','high')", incident, "Synthetic request matched CRS rule "+ev.Rules[0], ev.At)
		if e == nil {
			_, e = tx.Exec("INSERT OR IGNORE INTO incident_events VALUES(?,?)", incident, ev.ID)
		}
	}
	if e != nil {
		return e
	}
	_, e = tx.Exec("DELETE FROM events WHERE seq NOT IN (SELECT seq FROM events ORDER BY seq DESC LIMIT 50000) OR at < ?", time.Now().Add(-7*24*time.Hour).UTC().Format(time.RFC3339Nano))
	if e != nil {
		return e
	}
	return tx.Commit()
}

// Oversized records are drained without retaining their bytes. Partial final records
// remain at the previous cursor until the writer completes the newline.
func boundedLine(r *bufio.Reader) ([]byte, int64, bool, error) {
	b, e := r.ReadSlice('\n')
	n := int64(len(b))
	if e != bufio.ErrBufferFull {
		return b, n, len(b) > 8192, e
	}
	for e == bufio.ErrBufferFull {
		b, e = r.ReadSlice('\n')
		n += int64(len(b))
	}
	return nil, n, true, e
}
