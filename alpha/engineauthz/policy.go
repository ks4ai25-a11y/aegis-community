// SPDX-License-Identifier: Apache-2.0
// Package engineauthz implements Docker's native authorization protocol for an
// isolated experimental scanner daemon. It is not cleanup release authority.
package engineauthz

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineprofile"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"errors"
	"github.com/moby/moby/api/types/container"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Broker = "aegis-engine-broker"
const Observer = "aegis-engine-observer"
const api = "/v1.55"

var ErrPolicy = errors.New("scanner engine authorization refused")
var namePattern = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var pinPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$`)
var hashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var knownTools = map[string]bool{"bandit": true, "semgrep_ce": true, "gitleaks": true, "syft": true, "trivy": true, "osv_v2": true}

// Request is the native Docker authorization plugin envelope. Headers are not
// credentials. Only the daemon's TLS principal is accepted as client identity.
type Request struct {
	User                    string
	UserAuthNMethod         string
	RequestMethod           string
	RequestURI              string `json:"RequestUri"`
	RequestBody             []byte
	RequestHeaders          map[string]string
	RequestPeerCertificates [][]byte
	ResponseStatusCode      int
	ResponseBody            []byte
	ResponseHeaders         map[string]string
}
type Decision struct {
	Allow bool
	Msg   string
	Err   string
}
type Config struct {
	WorkRoot, JournalRoot, EngineDigest string
	UID, GID                            int
	Images                              map[string]string
	Live                                *LiveConfig
	Admitted                            *AdmittedConfig
}
type Policy struct {
	mu                           sync.Mutex
	config                       Config
	journal                      *enginejournal.Journal
	attempt                      *enginejournal.Attempt
	ticket                       *enginejournal.Ticket
	pending, operation, name, id string
	closed                       bool
	live                         *liveGate
	createBody                   []byte
	admitted                     *admittedGate
	mutation                     scanevidence.MutationIntent
	confirmedResponse            string
}

func Open(c Config) (*Policy, error) {
	if c.UID <= 0 || c.GID < 0 || !hashPattern.MatchString(c.EngineDigest) || len(c.Images) == 0 || len(c.Images) > 6 || !canonicalDir(c.WorkRoot) || c.WorkRoot == string(filepath.Separator) {
		return nil, ErrPolicy
	}
	rel, e := filepath.Rel(c.WorkRoot, c.JournalRoot)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, ErrPolicy
	}
	images := map[string]string{}
	for tool, image := range c.Images {
		if !knownTools[tool] || !pinPattern.MatchString(image) {
			return nil, ErrPolicy
		}
		images[tool] = image
	}
	c.Images = images
	// This root belongs only to the plugin, never to a broker or dispatcher.
	j, e := enginejournal.OpenExisting(c.JournalRoot, c.EngineDigest)
	if e != nil {
		return nil, ErrPolicy
	}
	if o := j.Observe(); o.Unresolved != 0 || o.Unfinished != 0 {
		j.Close()
		return nil, ErrPolicy
	}
	if c.Live != nil && c.Admitted != nil {
		j.Close()
		return nil, ErrPolicy
	}
	var admitted *admittedGate
	if c.Admitted != nil {
		admitted, e = openAdmitted(c, *c.Admitted)
		if e != nil {
			j.Close()
			return nil, ErrPolicy
		}
	}
	var live *liveGate
	if c.Live != nil {
		live, e = openLive(c, *c.Live)
		if e != nil {
			j.Close()
			return nil, ErrPolicy
		}
	}
	seal := ""
	if admitted != nil {
		seal = admitted.seal
	}
	if live != nil {
		seal = live.policy
	}
	if e = j.RequirePolicy(seal); e != nil {
		if admitted != nil {
			admitted.client.Close()
		}
		if live != nil {
			live.client.Close()
		}
		j.Close()
		return nil, ErrPolicy
	}
	c.Admitted = nil
	c.Live = nil // Retain only the private, validated configuration copy.
	return &Policy{config: c, journal: j, live: live, admitted: admitted}, nil
}
func canonicalDir(p string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n:,") {
		return false
	}
	actual, e := filepath.EvalSymlinks(p)
	st, se := os.Stat(p)
	return e == nil && actual == p && se == nil && st.IsDir()
}
func (p *Policy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		if p.admitted != nil {
			p.admitted.client.Close()
		}
		if p.live != nil {
			p.live.client.Close()
		}
		p.journal.Close()
	}
}
func (p *Policy) Observation() enginejournal.Observation { return p.journal.Observe() }
func deny() Decision                                     { return Decision{Msg: ErrPolicy.Error()} }
func allow() Decision                                    { return Decision{Allow: true} }
func fingerprint(r Request) string {
	b, _ := json.Marshal(struct {
		User, Method, URI string
		Body              []byte
	}{r.User, r.RequestMethod, r.RequestURI, r.RequestBody})
	return source.Hash(b)
}
func parsed(r Request) (*url.URL, bool) {
	if r.UserAuthNMethod != "TLS" || (r.User != Broker && r.User != Observer) || len(r.RequestURI) > 4096 || len(r.RequestBody) > 65536 {
		return nil, false
	}
	u, e := url.ParseRequestURI(r.RequestURI)
	if e != nil || u.Scheme != "" || u.Host != "" || u.RawPath != "" || u.Fragment != "" || u.ForceQuery || !strings.HasPrefix(u.Path, api+"/") {
		return nil, false
	}
	q, e := url.ParseQuery(u.RawQuery)
	return u, e == nil && q.Encode() == u.RawQuery
}
func exactQuery(u *url.URL, q url.Values) bool { return u.RawQuery == q.Encode() }
func (p *Policy) read(r Request, u *url.URL) bool {
	if len(r.RequestBody) != 0 {
		return false
	}
	if r.RequestMethod == "GET" && u.RawQuery == "" {
		if u.Path == api+"/info" {
			return true
		}
		for _, image := range p.config.Images {
			if u.Path == api+"/images/"+image+"/json" {
				return true
			}
		}
		if p.id != "" && (u.Path == api+"/containers/"+p.id+"/json" || u.Path == api+"/containers/"+p.name+"/json") {
			return true
		}
		if r.User == Observer && strings.HasPrefix(u.Path, api+"/containers/") && strings.HasSuffix(u.Path, "/json") {
			exact := strings.TrimSuffix(strings.TrimPrefix(u.Path, api+"/containers/"), "/json")
			return p.journal.KnownContainer(exact)
		}
	}
	if p.name != "" && r.RequestMethod == "GET" && u.Path == api+"/containers/json" {
		filter, _ := json.Marshal(map[string]map[string]bool{"name": {"^/" + p.name + "$": true}})
		return exactQuery(u, url.Values{"all": {"1"}, "filters": {string(filter)}})
	}
	if p.id != "" && r.User == Broker && r.RequestMethod == "POST" {
		if u.Path == api+"/containers/"+p.id+"/wait" {
			return exactQuery(u, url.Values{"condition": {"next-exit"}}) || exactQuery(u, url.Values{"condition": {"removed"}})
		}
		// Output only: the plugin authorizes the initial upgrade, never stream data.
		if u.Path == api+"/containers/"+p.id+"/attach" {
			return exactQuery(u, url.Values{"stream": {"1"}, "stdout": {"1"}, "stderr": {"1"}})
		}
	}
	return false
}
func (p *Policy) create(ctx context.Context, r Request, u *url.URL, now time.Time) bool {
	name := u.Query().Get("name")
	if !namePattern.MatchString(name) || !exactQuery(u, url.Values{"name": {name}}) || len(r.RequestBody) == 0 {
		return false
	}
	// Docker omits non-JSON bodies from the authz envelope. Require the precise
	// media type rather than accepting a body invisible to policy enforcement.
	contentType := ""
	for key, value := range r.RequestHeaders {
		if strings.EqualFold(key, "Content-Type") {
			if contentType != "" {
				return false
			}
			contentType = value
		}
	}
	if contentType != "application/json" {
		return false
	}
	var c container.CreateRequest
	if strict(r.RequestBody, &c, 65536) != nil || c.Config == nil || c.HostConfig == nil || len(c.Cmd) != 3 || len(c.HostConfig.Mounts) < 2 || len(c.HostConfig.Mounts) > 3 {
		return false
	}
	image, ok := p.config.Images[c.Cmd[0]]
	if !ok {
		return false
	}
	seconds, e := strconv.Atoi(c.Cmd[1])
	if e != nil || seconds < 1 || seconds > 120 || strconv.Itoa(seconds) != c.Cmd[1] {
		return false
	}
	deadline, e := time.Parse(time.RFC3339Nano, c.Cmd[2])
	if e != nil || len(c.Cmd[2]) > 35 || deadline.UTC().Format(time.RFC3339Nano) != c.Cmd[2] || !deadline.After(now) || deadline.After(now.Add(15*time.Minute)) {
		return false
	}
	pid, e := strconv.Atoi(c.Labels["io.aegis.operator_pid"])
	if e != nil || pid < 1 || strconv.Itoa(pid) != c.Labels["io.aegis.operator_pid"] {
		return false
	}
	paths := []string{}
	for _, m := range c.HostConfig.Mounts {
		rel, e := filepath.Rel(p.config.WorkRoot, m.Source)
		if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || !canonicalDir(m.Source) {
			return false
		}
		paths = append(paths, m.Source)
	}
	rules := ""
	if len(paths) == 3 {
		rules = paths[2]
	}
	expected := engineprofile.CreateTracked(c.Cmd[0], image, name, paths[0], rules, paths[1], seconds, deadline, p.config.UID, p.config.GID, pid)
	// Compare exact JSON object shapes as well as typed values: nulls, aliased or
	// additional keys and omitted safety fields cannot acquire zero-value meaning.
	var actual, prototype any
	if strict(r.RequestBody, &actual, 65536) != nil {
		return false
	}
	b, _ := json.Marshal(expected)
	_ = json.Unmarshal(b, &prototype)
	if !reflect.DeepEqual(actual, prototype) {
		return false
	}
	if p.live != nil && p.live.check(ctx, name, r.RequestBody) != nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	var admitted scanevidence.AuthorizerLaunch
	var mutation scanevidence.MutationIntent
	if p.admitted != nil {
		admitted, e = p.admitted.prepare(ctx, name, "create", r.RequestBody)
		if e != nil {
			return false
		}
		mutation, e = p.admitted.intent(admitted, fingerprint(r), "")
		if e != nil {
			return false
		}
	}
	a, e := p.journal.Begin(name, source.Hash(r.RequestBody))
	if e != nil {
		return false
	}
	p.attempt = a
	p.name = name
	p.id = ""
	var t *enginejournal.Ticket
	if p.admitted != nil {
		t, e = a.BeginBound("create", "", mutation)
	} else {
		t, e = a.Begin("create", "")
	}
	if e != nil {
		return false
	}
	p.ticket = t
	p.pending = fingerprint(r)
	p.operation = "create"
	p.createBody = append([]byte(nil), r.RequestBody...)
	if p.admitted != nil {
		p.mutation = mutation
		if p.admitted.admit(ctx, admitted, mutation) != nil {
			return false
		}
	}
	return ctx.Err() == nil
}
func (p *Policy) AuthorizeRequest(r Request) Decision {
	return p.AuthorizeRequestContext(context.Background(), r)
}

func (p *Policy) AuthorizeRequestContext(ctx context.Context, r Request) Decision {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil {
		return deny()
	}
	u, ok := parsed(r)
	if !ok {
		return deny()
	}
	if p.read(r, u) {
		return allow()
	}
	if r.User != Broker || p.pending != "" {
		return deny()
	}
	if r.RequestMethod == "POST" && u.Path == api+"/containers/create" && p.attempt == nil {
		if p.create(ctx, r, u, time.Now()) {
			return allow()
		}
		return deny()
	}
	if p.attempt == nil || p.id == "" || len(r.RequestBody) != 0 {
		return deny()
	}
	operation := ""
	if r.RequestMethod == "POST" && u.Path == api+"/containers/"+p.id+"/start" && u.RawQuery == "" {
		operation = "start"
	}
	if r.RequestMethod == "DELETE" && u.Path == api+"/containers/"+p.id && exactQuery(u, url.Values{"force": {"1"}, "v": {"1"}}) {
		operation = "remove"
	}
	if operation == "" {
		return deny()
	}
	// Cleanup remains available for the tracked allocation even after lease
	// expiry or cancellation; a new start always obtains a new observation.
	if operation == "start" && p.live != nil && p.live.check(ctx, p.name, p.createBody) != nil {
		return deny()
	}
	if ctx.Err() != nil {
		return deny()
	}
	var admitted scanevidence.AuthorizerLaunch
	var mutation scanevidence.MutationIntent
	var e error
	if p.admitted != nil {
		admitted, e = p.admitted.prepare(ctx, p.name, operation, p.createBody)
		if e != nil || admitted.Launch.Digest != p.mutation.Request.Launch || admitted.Generation.ID != p.mutation.Request.Generation {
			return deny()
		}
		mutation, e = p.admitted.intent(admitted, fingerprint(r), p.id)
		if e != nil {
			return deny()
		}
	}
	var ticket *enginejournal.Ticket
	if p.admitted != nil {
		ticket, e = p.attempt.BeginBound(operation, p.id, mutation)
	} else {
		ticket, e = p.attempt.Begin(operation, p.id)
	}

	if e != nil {
		return deny()
	}
	p.ticket = ticket
	p.pending = fingerprint(r)
	p.operation = operation
	if p.admitted != nil {
		p.mutation = mutation
		if p.admitted.admit(ctx, admitted, mutation) != nil {
			return deny()
		}
	}
	if ctx.Err() != nil {
		return deny()
	}
	return allow()
}
func (p *Policy) AuthorizeResponse(r Request) Decision {
	return p.AuthorizeResponseContext(context.Background(), r)
}
func (p *Policy) AuthorizeResponseContext(ctx context.Context, r Request) Decision {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return deny()
	}
	u, ok := parsed(r)
	if !ok {
		return deny()
	}
	if p.read(r, u) {
		return allow()
	}
	if p.ticket == nil || p.pending != fingerprint(r) || len(r.ResponseBody) > 65536 {
		return deny()
	}
	id := p.id
	if p.operation == "create" {
		var created container.CreateResponse
		if strict(r.ResponseBody, &created, 65536) != nil || !idPattern.MatchString(created.ID) {
			return deny()
		}
		id = created.ID
	} else if len(r.ResponseBody) != 0 || p.operation == "remove" && r.ResponseStatusCode != 204 {
		return deny()
	}

	responseBytes, _ := json.Marshal(struct {
		Status int
		Body   []byte
	}{r.ResponseStatusCode, r.ResponseBody})
	responseFingerprint := source.Hash(responseBytes)
	if p.confirmedResponse != "" && p.confirmedResponse != responseFingerprint {
		return deny()
	}
	if p.confirmedResponse == "" {
		if p.ticket.Confirm(r.ResponseStatusCode, id) != nil {
			return deny()
		}
		p.confirmedResponse = responseFingerprint
	}
	if p.admitted != nil {
		digest, e := p.ticket.ResponseDigest()
		if e != nil {
			return deny()
		}
		_, e = p.admitted.client.Complete(ctx, scanevidence.MutationCompletion{Intent: p.mutation.ID, Generation: p.mutation.Request.Generation, Status: r.ResponseStatusCode, EngineID: id, Response: digest})
		if e != nil || ctx.Err() != nil {
			return deny()
		}
	}
	p.id = id
	p.pending = ""
	p.ticket = nil
	if p.operation == "remove" {
		if p.attempt.Finish() != nil {
			return deny()
		}
		p.attempt = nil
		p.createBody = nil
	}
	p.operation = ""
	p.confirmedResponse = ""
	return allow()
}
