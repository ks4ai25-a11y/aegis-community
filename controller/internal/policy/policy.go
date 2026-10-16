// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var parameter = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,31}$`)

var (
	siteID      = regexp.MustCompile(`^site_[a-z0-9_]{1,32}$`)
	hostname    = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	origin      = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{1,5})$`)
	exactRoute  = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+){0,15}$`)
	email       = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	displayName = regexp.MustCompile(`^[A-Za-z0-9 ._()-]{1,64}$`)
)

// Hosts the bundled demo answers on; registered sites cannot claim them.
var demoHosts = []string{"localhost", "127.0.0.1", "demo.example.test"}

// Service names inside the Aegis deployment that must never be used as an origin.
var reservedOrigins = map[string]bool{"controller": true, "policy-deployer": true, "gateway": true, "fixture-worker": true, "localhost": true, "metadata.google.internal": true}

func validateCRS(c domain.CRS) error {
	if c.Blocking < 1 || c.Blocking > 4 || c.Executing < c.Blocking || c.Executing > 4 || c.Threshold < 5 || c.Threshold > 20 {
		return fmt.Errorf("CRS settings outside supported bounds")
	}
	return nil
}

func validateExclusions(xs []domain.Exclusion, demo bool) error {
	if len(xs) > 8 {
		return fmt.Errorf("at most eight scoped exclusions")
	}
	for _, x := range xs {
		if demo {
			if x.RuleID != 942100 && x.RuleID != 941100 {
				return fmt.Errorf("only reviewed rule IDs 942100 and 941100 are supported")
			}
			if x.Path != "/catalog" && x.Path != "/test-pattern" {
				return fmt.Errorf("unsupported exclusion route")
			}
		} else {
			// Detection rules only (protocol enforcement through attack families);
			// anomaly-scoring/blocking evaluation rules cannot be excluded.
			if x.RuleID < 920000 || x.RuleID > 944999 {
				return fmt.Errorf("exclusions may target CRS detection rules 920000–944999 only")
			}
			if !exactRoute.MatchString(x.Path) {
				return fmt.Errorf("exclusions require an exact, non-root route")
			}
		}
		if x.Method != "GET" && x.Method != "POST" {
			return fmt.Errorf("unsupported method")
		}
		if !parameter.MatchString(x.Parameter) {
			return fmt.Errorf("invalid parameter target")
		}
		if x.ExpiresAt != "" {
			if t, e := time.Parse(time.RFC3339, x.ExpiresAt); e != nil || t.UTC().Format(time.RFC3339) != x.ExpiresAt {
				return fmt.Errorf("expires_at must be a UTC RFC 3339 time such as 2026-11-01T00:00:00Z")
			}
		}
	}
	return nil
}

// ValidOrigin accepts host:port for a private origin reachable from the gateway
// network. Loopback, link-local/metadata and Aegis service names are refused.
func ValidOrigin(o string) error {
	m := origin.FindStringSubmatch(o)
	if m == nil {
		return fmt.Errorf("origin must be host:port")
	}
	host := m[1]
	port, e := strconv.Atoi(m[2])
	if e != nil || port < 1 || port > 65535 {
		return fmt.Errorf("origin port out of range")
	}
	if reservedOrigins[host] || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("origin is reserved")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || ip.To4() == nil {
			return fmt.Errorf("origin address is not allowed")
		}
	}
	return nil
}

func validateSite(s domain.SitePolicy) error {
	if !siteID.MatchString(s.ID) || s.ID == "site_demo" {
		return fmt.Errorf("site_id must match site_[a-z0-9_] and not be site_demo")
	}
	if !displayName.MatchString(s.Name) {
		return fmt.Errorf("display name must be 1–64 plain characters")
	}
	if len(s.Hostnames) < 1 || len(s.Hostnames) > 8 {
		return fmt.Errorf("each site needs 1–8 host names")
	}
	for _, h := range s.Hostnames {
		if len(h) > 253 || !hostname.MatchString(h) {
			return fmt.Errorf("invalid host name %q", h)
		}
	}
	if e := ValidOrigin(s.Origin); e != nil {
		return e
	}
	if s.Mode != "observe" && s.Mode != "protect" {
		return fmt.Errorf("mode must be observe or protect")
	}
	if e := validateCRS(s.CRS); e != nil {
		return e
	}
	switch s.TLS {
	case "", "internal":
		if s.ACMEEmail != "" {
			return fmt.Errorf("acme_email is only used with tls \"acme\"")
		}
	case "acme":
		if s.ACMEEmail != "" && !email.MatchString(s.ACMEEmail) {
			return fmt.Errorf("invalid ACME contact email")
		}
	default:
		return fmt.Errorf("tls must be empty, \"acme\" or \"internal\"")
	}
	if l := s.RateLimit; l != nil && (l.Requests < 10 || l.Requests > 100000 || l.WindowSeconds < 1 || l.WindowSeconds > 3600) {
		return fmt.Errorf("rate limit must allow 10–100000 requests per 1–3600 seconds")
	}
	return validateExclusions(s.Exclusions, false)
}

func Validate(p domain.Policy) error {
	if (p.Schema != "1.0" && p.Schema != "1.1") || p.Site != "site_demo" {
		return fmt.Errorf("unsupported policy schema or site")
	}
	if p.Schema == "1.0" && (p.Sites != nil || p.TrustedProxies != nil) {
		return fmt.Errorf("registered sites and trusted proxies require schema 1.1")
	}
	if e := validateProxies(p.TrustedProxies); e != nil {
		return e
	}
	if p.Mode != "observe" && p.Mode != "protect" {
		return fmt.Errorf("mode must be observe or protect")
	}
	if e := validateCRS(p.CRS); e != nil {
		return e
	}
	if len(p.Metadata.Rationale) < 5 || len(p.Metadata.Rationale) > 512 {
		return fmt.Errorf("provide a rationale of 5–512 characters")
	}
	if e := validateExclusions(p.Exclusions, true); e != nil {
		return e
	}
	if len(p.Sites) > 16 {
		return fmt.Errorf("at most sixteen registered sites")
	}
	ids := map[string]bool{}
	hosts := map[string]bool{}
	for _, h := range demoHosts {
		hosts[h] = true
	}
	for _, s := range p.Sites {
		if e := validateSite(s); e != nil {
			return fmt.Errorf("%s: %w", s.ID, e)
		}
		if ids[s.ID] {
			return fmt.Errorf("duplicate site %s", s.ID)
		}
		ids[s.ID] = true
		for _, h := range s.Hostnames {
			if hosts[h] {
				return fmt.Errorf("host name %s is claimed twice", h)
			}
			hosts[h] = true
		}
	}
	return nil
}

// validateProxies accepts canonical CIDR prefixes only. A range that trusts
// everyone (or the whole IPv4/IPv6 space) would let any client choose its address.
func validateProxies(cidrs []string) error {
	if len(cidrs) > 64 {
		return fmt.Errorf("at most 64 trusted proxy ranges")
	}
	seen := map[string]bool{}
	for _, c := range cidrs {
		prefix, e := netip.ParsePrefix(c)
		if e != nil || prefix.Masked().String() != c {
			return fmt.Errorf("trusted proxy %q must be a canonical CIDR such as 10.0.0.0/8", c)
		}
		if (prefix.Addr().Is4() && prefix.Bits() < 8) || (prefix.Addr().Is6() && prefix.Bits() < 16) {
			return fmt.Errorf("trusted proxy range %s is too broad", c)
		}
		if seen[c] {
			return fmt.Errorf("duplicate trusted proxy %s", c)
		}
		seen[c] = true
	}
	return nil
}

// Expired returns the policy with exclusions past their expiry removed, and
// whether anything was removed.
func Expired(p domain.Policy, now time.Time) (domain.Policy, bool) {
	keep := func(xs []domain.Exclusion) ([]domain.Exclusion, bool) {
		out, changed := []domain.Exclusion{}, false
		for _, x := range xs {
			if t, e := time.Parse(time.RFC3339, x.ExpiresAt); x.ExpiresAt != "" && e == nil && !now.Before(t) {
				changed = true
				continue
			}
			out = append(out, x)
		}
		return out, changed
	}
	b, _ := json.Marshal(p)
	var c domain.Policy
	json.Unmarshal(b, &c)
	var changed bool
	c.Exclusions, changed = keep(c.Exclusions)
	for i := range c.Sites {
		var ch bool
		c.Sites[i].Exclusions, ch = keep(c.Sites[i].Exclusions)
		changed = changed || ch
	}
	return c, changed
}

// FutureExpiries refuses a candidate that introduces an already-expired exclusion.
func FutureExpiries(p domain.Policy, now time.Time) error {
	check := func(xs []domain.Exclusion) error {
		for _, x := range xs {
			if t, e := time.Parse(time.RFC3339, x.ExpiresAt); x.ExpiresAt != "" && e == nil && !now.Before(t) {
				return fmt.Errorf("exclusion for rule %d on %s already expired", x.RuleID, x.Path)
			}
		}
		return nil
	}
	if e := check(p.Exclusions); e != nil {
		return e
	}
	for _, s := range p.Sites {
		if e := check(s.Exclusions); e != nil {
			return e
		}
	}
	return nil
}

// ProtectRequiresObservation refuses Protect for a site that was not already
// governed (in Observe or Protect) by the parent revision, so blocking never
// starts on traffic Aegis has not yet observed.
func ProtectRequiresObservation(parent, candidate domain.Policy) error {
	for _, s := range candidate.Sites {
		if s.Mode != "protect" {
			continue
		}
		if _, ok := parent.FindSite(s.ID); !ok {
			return fmt.Errorf("%s: register a new site in observe mode before enabling protect", s.ID)
		}
	}
	return nil
}

type block struct {
	matcher, prefix, mode, origin string
	hosts                         []string
	crs                           domain.CRS
	exclusions                    []domain.Exclusion
	tls, email                    string
	limit                         *domain.RateLimit
}

func blocks(p domain.Policy, demoOrigin string) []block {
	out := []block{{matcher: "owned", mode: p.Mode, origin: demoOrigin, hosts: demoHosts, crs: p.CRS, exclusions: p.Exclusions}}
	for _, s := range p.Sites {
		// Registered sites prefix their request IDs with the site ID so WAF and
		// access records can be attributed without trusting any client header.
		out = append(out, block{s.ID, s.ID + ".", s.Mode, s.Origin, s.Hostnames, s.CRS, s.Exclusions, s.TLS, s.ACMEEmail, s.RateLimit})
	}
	return out
}

// route renders the ordered handler chain for one site: trusted identity, hard
// limits and the approved rate limit precede the WAF, which precedes the origin.
func route(b block, digest, indent string) string {
	engine := "DetectionOnly"
	if b.mode == "protect" {
		engine = "On"
	}
	exclusions := ""
	for i, x := range b.exclusions {
		exclusions += fmt.Sprintf("SecRule REQUEST_METHOD \"@streq %s\" \"id:%d,phase:1,pass,nolog,chain\"\nSecRule REQUEST_URI \"@rx ^%s(?:[?]|$)\" \"chain\"\nSecRule &ARGS:%s \"@ge 0\" \"ctl:ruleRemoveTargetById=%d;ARGS:%s\"\n", x.Method, 10000+i, regexp.QuoteMeta(x.Path), x.Parameter, x.RuleID, x.Parameter)
	}
	limit := ""
	if b.limit != nil {
		limit = fmt.Sprintf(`
   rate_limit {
    zone %s {
     key {http.vars.client_ip}
     events %d
     window %ds
    }
   }`, b.matcher, b.limit.Requests, b.limit.WindowSeconds)
	}
	body := fmt.Sprintf(`route {
   request_header -X-Forwarded-For
   request_header -Forwarded
   request_header -X-Real-IP
   request_header -X-Request-ID
   request_header -X-Aegis-Request-ID
   request_header X-Aegis-Request-ID %s{http.request.uuid}
   header X-Aegis-Request-ID %s{http.request.uuid}
   header X-Aegis-Revision %s
   header X-Aegis-Mode %s%s
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
  }`, b.prefix, b.prefix, digest, b.mode, limit, engine, b.crs.Blocking, b.crs.Executing, b.crs.Threshold, exclusions, b.origin)
	return indent + body
}

func errorResponse(b block, digest string) string {
	return fmt.Sprintf("   header X-Aegis-Request-ID %s{http.request.uuid}\n   header X-Aegis-Revision %s\n   header X-Aegis-Mode %s\n   respond \"Request could not be processed\" {http.error.status_code}\n", b.prefix, digest, b.mode)
}

const logBlock = ` log {
  output aegis {
   path %s
  }
  format json
 }
`

// Render produces the production gateway configuration: sites with TLS get their
// own HTTPS site blocks (certificates under the gateway's private data volume).
func Render(p domain.Policy, origin, listen, admin, log string) string {
	return render(p, origin, listen, admin, log, true)
}

// RenderFixture keeps every site on the plain HTTP listener so the isolated
// fixture never binds HTTPS ports or contacts a certificate authority.
func RenderFixture(p domain.Policy, origin, listen, admin, log string) string {
	return render(p, origin, listen, admin, log, false)
}

// HTTPSPort is the TLS listener inside the gateway container; publish host port
// 443 to it. The HTTP port is the shared listener's port (8080 in the reference
// deployment), which also answers ACME HTTP-01 challenges and HTTPS redirects.
var HTTPSPort = 8443

func render(p domain.Policy, origin, listen, admin, log string, withTLS bool) string {
	digest := domain.Digest(p)
	routes, errs, secure := "", "", ""
	anyTLS := false
	for _, b := range blocks(p, origin) {
		if withTLS && b.tls != "" {
			anyTLS = true
			names := []string{}
			for _, h := range b.hosts {
				names = append(names, "https://"+h)
			}
			issuer := "internal"
			if b.tls == "acme" {
				issuer = b.email
			}
			tls := ""
			if issuer != "" {
				tls = " tls " + issuer + "\n"
			}
			secure += fmt.Sprintf("%s {\n%s%s\n handle_errors {\n%s }\n"+logBlock+"}\n", strings.Join(names, ", "), tls, route(b, digest, " "), errorResponse(b, digest), log)
			// Explicit redirect on the shared listener; implicit redirects are disabled.
			routes += fmt.Sprintf(" @%s_https host %s\n redir @%s_https https://{host}{uri} 308\n", b.matcher, strings.Join(b.hosts, " "), b.matcher)
			continue
		}
		routes += fmt.Sprintf(" @%s host %s\n handle @%s {\n%s\n }\n", b.matcher, strings.Join(b.hosts, " "), b.matcher, route(b, digest, "  "))
		if b.prefix != "" {
			errs += fmt.Sprintf("  @%s_error host %s\n  handle @%s_error {\n%s  }\n", b.matcher, strings.Join(b.hosts, " "), b.matcher, errorResponse(b, digest))
		}
	}
	global, protocols := " auto_https off\n", "h1 h2c"
	proxies := ""
	if len(p.TrustedProxies) > 0 {
		// Only these peers may supply X-Forwarded-For; the leftmost untrusted
		// address becomes the client address used for pseudonyms and rate limits.
		proxies = "\n  trusted_proxies static " + strings.Join(p.TrustedProxies, " ") + "\n  client_ip_headers X-Forwarded-For\n  trusted_proxies_strict"
	}
	if anyTLS {
		// Certificates are managed only for the TLS site blocks; their HTTP names
		// redirect to HTTPS on the shared listener and ACME HTTP-01 uses it too.
		port := listen[strings.LastIndex(listen, ":")+1:]
		// skip_install_trust: the internal CA is never added to any system trust store.
		global = fmt.Sprintf(" http_port %s\n https_port %d\n auto_https disable_redirects\n skip_install_trust\n", port, HTTPSPort)
		protocols = "h1 h2 h2c"
	}
	return fmt.Sprintf(`{
%s admin unix/%s
 log default {
  level INFO
  output aegis {
   path %s
  }
  format json
 }
 servers {
  max_header_size 32KB
  protocols %s%s
  timeouts {
   read_header 5s
   read_body 15s
   idle 60s }
 }
}
http://%s {
%s handle {
  respond "Unknown host" 421
 }
 handle_errors {
%s  handle {
   header X-Aegis-Request-ID {http.request.uuid}
   header X-Aegis-Revision %s
   header X-Aegis-Mode %s
   respond "Request could not be processed" {http.error.status_code}
  }
 }
`+logBlock+`}
%s`, global, admin, log, protocols, proxies, listen, routes, errs, digest, p.Mode, log, secure)
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
		if errors.Is(e, ErrDeployerBusy) {
			// Nothing was applied, so no rollback (and no freeze) is needed.
			m.S.DB.Exec("UPDATE policies SET state='PENDING_APPROVAL' WHERE digest=? AND state='APPLYING'", d)
			m.S.Set("apply_journal", "")
			return e
		}
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

// ErrDeployerBusy is definitive: the deployer refused before touching the gateway.
var ErrDeployerBusy = errors.New("policy deployer busy; no gateway change attempted")

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
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", ErrDeployerBusy
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("deployer: %s", out.Error)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(out.Digest) {
		return "", fmt.Errorf("invalid deployer digest")
	}
	return out.Digest, nil
}
