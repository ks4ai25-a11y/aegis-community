// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var parameter = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,31}$`)

func Validate(p domain.Policy) error {
	if p.Schema != "1.0" || p.Site != "site_demo" {
		return fmt.Errorf("unsupported policy schema or site")
	}
	if p.Mode != "observe" && p.Mode != "protect" {
		return fmt.Errorf("mode must be observe or protect")
	}
	if p.CRS.Blocking < 1 || p.CRS.Blocking > 4 || p.CRS.Executing < p.CRS.Blocking || p.CRS.Executing > 4 || p.CRS.Threshold < 5 || p.CRS.Threshold > 20 {
		return fmt.Errorf("CRS settings outside supported bounds")
	}
	if len(p.Metadata.Rationale) < 5 || len(p.Metadata.Rationale) > 512 {
		return fmt.Errorf("provide a rationale of 5–512 characters")
	}
	if len(p.Exclusions) > 8 {
		return fmt.Errorf("at most eight scoped exclusions")
	}
	for _, x := range p.Exclusions {
		if x.RuleID != 942100 && x.RuleID != 941100 {
			return fmt.Errorf("only reviewed rule IDs 942100 and 941100 are supported")
		}
		if x.Method != "GET" && x.Method != "POST" {
			return fmt.Errorf("unsupported method")
		}
		if x.Path != "/catalog" && x.Path != "/test-pattern" {
			return fmt.Errorf("unsupported exclusion route")
		}
		if !parameter.MatchString(x.Parameter) {
			return fmt.Errorf("invalid parameter target")
		}
	}
	return nil
}
func Render(p domain.Policy, origin, listen, admin, log string) string {
	engine := "DetectionOnly"
	if p.Mode == "protect" {
		engine = "On"
	}
	digest := domain.Digest(p)
	exclusions := ""
	for i, x := range p.Exclusions {
		exclusions += fmt.Sprintf("SecRule REQUEST_METHOD \"@streq %s\" \"id:%d,phase:1,pass,nolog,chain\"\nSecRule REQUEST_URI \"@rx ^%s(?:[?]|$)\" \"chain\"\nSecRule &ARGS:%s \"@ge 0\" \"ctl:ruleRemoveTargetById=%d;ARGS:%s\"\n", x.Method, 10000+i, regexp.QuoteMeta(x.Path), x.Parameter, x.RuleID, x.Parameter)
	}
	// route blocks make ordering explicit: trusted identity and hard limits precede WAF.
	return fmt.Sprintf(`{
 auto_https off
 admin unix/%s
 log default {
  level INFO
  output aegis {
   path %s
  }
  format json
 }
 servers {
  max_header_size 32KB
  protocols h1 h2c
  timeouts {
   read_header 5s
   read_body 15s
   idle 60s }
 }
}
http://%s {
 @owned host localhost 127.0.0.1 demo.example.test
 handle @owned {
  route {
   request_header -X-Forwarded-For
   request_header -Forwarded
   request_header -X-Real-IP
   request_header -X-Request-ID
   request_header -X-Aegis-Request-ID
   request_header X-Aegis-Request-ID {http.request.uuid}
   header X-Aegis-Request-ID {http.request.uuid}
   header X-Aegis-Revision %s
   header X-Aegis-Mode %s
   request_body {
    max_size 1MB
   }
   coraza_waf {
    load_owasp_crs
    tx_id_req_header X-Aegis-Request-ID
    directives `+"`"+`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecRuleEngine %s
SecAuditEngine Off
SecDebugLogLevel 0
SecResponseBodyAccess Off
SecRequestBodyLimit 1048576
SecRequestBodyNoFilesLimit 1048576
SecRequestBodyLimitAction Reject
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d"
%s
Include @owasp_crs/*.conf
`+"`"+`
   }
   reverse_proxy %s {
    header_up -X-Aegis-Revision
    transport http {
     dial_timeout 3s
     response_header_timeout 15s }
   }
  }
 }
 handle {
  respond "Unknown host" 421
 }
 handle_errors {
  header X-Aegis-Request-ID {http.request.uuid}
  header X-Aegis-Revision %s
  header X-Aegis-Mode %s
  respond "Request could not be processed" {http.error.status_code}
 }
 log {
  output aegis {
   path %s
  }
  format json
 }
}
`, admin, log, listen, digest, p.Mode, engine, p.CRS.Blocking, p.CRS.Executing, p.CRS.Threshold, exclusions, origin, digest, p.Mode, log)
}
func Atomic(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".stage-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, path)
	}
	if e == nil {
		d, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		e = d.Sync()
		d.Close()
	}
	return e
}

type Manager struct {
	S                                         *store.Store
	Root, Binary, Socket, Origin, Listen, Log string
	mu                                        sync.Mutex
	Frozen                                    atomic.Bool
	DeploySocket                              string
}

func (m *Manager) Client() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", m.Socket)
	}}}
}
func (m *Manager) Active(ctx context.Context) (string, error) {
	if m.DeploySocket != "" {
		return m.Remote(ctx, "status", domain.Policy{})
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/config/", nil)
	resp, e := m.Client().Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if e != nil {
		return "", e
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("gateway unavailable")
	}
	var raw any
	if json.Unmarshal(b, &raw) != nil {
		return "", fmt.Errorf("invalid gateway configuration")
	}
	var find func(any) string
	find = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			for k, a := range x {
				if strings.EqualFold(k, "X-Aegis-Revision") {
					if vs, ok := a.([]any); ok && len(vs) > 0 {
						if d, ok := vs[0].(string); ok {
							return d
						}
					}
				}
				if d := find(a); d != "" {
					return d
				}
			}
		case []any:
			for _, a := range x {
				if d := find(a); d != "" {
					return d
				}
			}
		}
		return ""
	}
	d := find(raw)
	if d == "" {
		return "", fmt.Errorf("revision not attested")
	}
	return d, nil
}
func (m *Manager) Prepare(ctx context.Context, p domain.Policy) (string, error) {
	if m.DeploySocket != "" {
		return m.Remote(ctx, "validate", p)
	}
	if e := Validate(p); e != nil {
		return "", e
	}
	d := domain.Digest(p)
	path := filepath.Join(m.Root, strings.TrimPrefix(d, "sha256:"), "Caddyfile")
	if e := Atomic(path, []byte(Render(p, m.Origin, m.Listen, m.Socket, m.Log))); e != nil {
		return "", e
	}
	cmd := exec.CommandContext(ctx, m.Binary, "validate", "--config", path, "--adapter", "caddyfile")
	if e := cmd.Run(); e != nil {
		return "", fmt.Errorf("gateway rejected candidate configuration")
	}
	return d, nil
}
func (m *Manager) Reload(ctx context.Context, p domain.Policy) error {
	if m.DeploySocket != "" {
		_, e := m.Remote(ctx, "apply", p)
		return e
	}
	path := filepath.Join(m.Root, strings.TrimPrefix(domain.Digest(p), "sha256:"), "Caddyfile")
	cmd := exec.CommandContext(ctx, m.Binary, "adapt", "--config", path, "--adapter", "caddyfile")
	b, e := cmd.Output()
	if e != nil {
		return e
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/load", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, e := m.Client().Do(req)
	if e != nil {
		return e
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("reload failed")
	}
	got, e := m.Active(ctx)
	if e != nil || got != domain.Digest(p) {
		return fmt.Errorf("active revision unknown")
	}
	return nil
}
func (m *Manager) Apply(ctx context.Context, p domain.Policy, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Frozen.Load() {
		return fmt.Errorf("policy changes frozen pending reconciliation")
	}
	old, active, e := m.S.Active()
	if e != nil {
		return e
	}
	if p.Parent != active {
		return fmt.Errorf("stale parent revision")
	}
	d, e := m.Prepare(ctx, p)
	if e != nil {
		return e
	}
	if got, e := m.Active(ctx); e != nil || got != active {
		return fmt.Errorf("gateway revision does not match controller")
	}

	if e = m.S.Audit(actor, "policy.activation_approved", d, "PENDING_ACTIVATION", map[string]string{"parent": active}); e != nil {
		return fmt.Errorf("approval could not be recorded")
	}
	journal, e := m.S.DB.Begin()
	if e != nil {
		return e
	}
	res, e := journal.Exec("UPDATE policies SET state='APPLYING' WHERE digest=? AND state='PENDING_APPROVAL'", d)
	if e == nil {
		n, _ := res.RowsAffected()
		if n != 1 {
			e = fmt.Errorf("candidate is not pending approval")
		}
	}
	if e == nil {
		_, e = journal.Exec("INSERT INTO settings VALUES('apply_journal',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", d)
	}
	if e == nil {
		e = journal.Commit()
	} else {
		journal.Rollback()
	}
	if e != nil {
		return fmt.Errorf("durable activation journal unavailable: %w", e)
	}

	if e = m.Reload(ctx, p); e != nil {
		if re := m.Reload(ctx, old); re != nil {
			m.Frozen.Store(true)
			m.S.Set("apply_frozen", "true")
			return fmt.Errorf("APPLY_STATUS_UNKNOWN: reload and recovery could not be confirmed")
		}
		m.S.DB.Exec("UPDATE policies SET state='FAILED' WHERE digest=?", d)
		m.S.Set("apply_journal", "")
		return e
	}
	tx, e := m.S.DB.Begin()
	if e != nil {
		m.Frozen.Store(true)
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec("UPDATE policies SET state='SUPERSEDED' WHERE digest=?", active)
	if e == nil {
		_, e = tx.Exec("UPDATE policies SET state='ACTIVE' WHERE digest=?", d)
	}
	if e == nil {
		_, e = tx.Exec("UPDATE settings SET value=? WHERE key='active' AND value=?", d, active)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		m.Frozen.Store(true)
		return e
	}
	m.S.Set("apply_journal", "")

	if e = m.S.Audit(actor, "policy.activate", d, "ACTIVE", map[string]string{"before": active, "after": d}); e != nil {
		m.Frozen.Store(true)
		return fmt.Errorf("active policy confirmed but audit storage degraded")
	}
	return nil
}
func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, d, e := m.S.Active()
	if e != nil {
		return e
	}
	got, e := m.Active(ctx)
	if e != nil {
		return e
	}

	// Finish a durably approved operation if the helper confirmed it before a crash.
	if journal, je := m.S.Get("apply_journal"); je == nil && journal != "" && journal != d && got == journal {
		candidate, pe := m.S.Policy(journal)
		var state string
		se := m.S.DB.QueryRow("SELECT state FROM policies WHERE digest=?", journal).Scan(&state)
		if pe != nil || se != nil || state != "APPLYING" || domain.Digest(candidate) != journal || candidate.Parent != d {
			m.Frozen.Store(true)
			return fmt.Errorf("activation journal cannot be reconciled")
		}
		tx, te := m.S.DB.Begin()
		if te != nil {
			return te
		}
		_, te = tx.Exec("UPDATE policies SET state='SUPERSEDED' WHERE digest=?", d)
		if te == nil {
			_, te = tx.Exec("UPDATE policies SET state='ACTIVE' WHERE digest=?", journal)
		}
		if te == nil {
			_, te = tx.Exec("UPDATE settings SET value=? WHERE key='active'", journal)
		}
		if te == nil {
			te = tx.Commit()
		} else {
			tx.Rollback()
		}
		if te != nil {
			m.Frozen.Store(true)
			return te
		}
		d = journal
		p = candidate
		if te = m.S.Audit("system", "policy.activation_reconciled", d, "ACTIVE", nil); te != nil {
			return te
		}
	}
	if got != d {
		if _, e = m.Prepare(ctx, p); e != nil {
			return e
		}
		if e = m.Reload(ctx, p); e != nil {
			m.Frozen.Store(true)
			return e
		}
	}
	m.S.Set("apply_journal", "")
	m.S.Set("apply_frozen", "false")
	m.Frozen.Store(false)
	return nil
}

// Remote exposes only typed policy operations; callers cannot submit Caddy JSON or paths.
func (m *Manager) Remote(ctx context.Context, operation string, p domain.Policy) (string, error) {
	expected := ""
	if operation == "apply" {
		var e error
		expected, e = m.Remote(ctx, "status", domain.Policy{})
		if e != nil {
			return "", e
		}
	}
	b, err := json.Marshal(struct {
		Policy   domain.Policy `json:"policy"`
		Expected string        `json:"expected_revision"`
	}{p, expected})
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", m.DeploySocket)
	}}}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://deployer/"+operation, strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("policy deployer unavailable")
	}
	defer resp.Body.Close()
	var out struct {
		Digest string `json:"digest"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return "", fmt.Errorf("invalid deployer response")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("deployer: %s", out.Error)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(out.Digest) {
		return "", fmt.Errorf("invalid deployer digest")
	}
	return out.Digest, nil
}
