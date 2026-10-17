// SPDX-License-Identifier: Apache-2.0
// Package workerchannel is the scanner-side private protocol. It has no
// controller database dependency and never sends credentials over TCP.
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrEmpty = errors.New("no scanner job available")
var hashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var jobPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var workerPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
var tools = map[string]bool{"bandit": true, "gitleaks": true, "osv_v2": true, "semgrep_ce": true, "syft": true, "trivy": true}

const maxResponse = 8 << 20 // Bounded application maps can contain 10,000 files.

type Input struct {
	Schema     string   `json:"schema_version"`
	App        string   `json:"app_id"`
	Repository string   `json:"repository_id"`
	MapDigest  string   `json:"map_digest"`
	Mode       string   `json:"mode"`
	Tools      []string `json:"tool_ids"`
	Duration   int      `json:"tool_timeout_seconds"`
}
type Job struct {
	Schema          string `json:"schema_version"`
	ID              string `json:"job_id"`
	Owner           string `json:"owner_id"`
	Input           Input  `json:"input"`
	LockDigest      string `json:"tool_lock_digest"`
	RequestDigest   string `json:"request_digest"`
	State           string `json:"state"`
	CancelRequested bool   `json:"cancel_requested"`
	Created         string `json:"created_at"`
	Expires         string `json:"expires_at"`
	Finished        string `json:"finished_at,omitempty"`
	Error           string `json:"error_code,omitempty"`
}
type Identity struct {
	ID      string `json:"worker_id"`
	Owner   string `json:"owner_id"`
	State   string `json:"state"`
	Expires string `json:"expires_at"`
	Created string `json:"created_at"`
}

// Lease keeps its capability out of ordinary JSON serialization. Claim decoding
// uses an explicit private DTO, just as the server does.
type Lease struct {
	Job      Job
	Map      source.Map
	Token    string `json:"-"`
	Deadline time.Time
	Guards   scanevidence.GuardSet
}
type Client struct {
	socket, credential, owner, lock string
	http                            *http.Client
	transport                       *http.Transport
}

func New(socket, credential, owner, lock string) (*Client, error) {
	canonical, pathErr := filepath.EvalSymlinks(filepath.Dir(credential))
	if !filepath.IsAbs(credential) || filepath.Clean(credential) != credential || pathErr != nil || canonical != filepath.Dir(credential) {
		return nil, errors.New("explicit canonical credential path required")
	}
	if owner == "" || len(owner) > 128 || !hashPattern.MatchString(lock) || validateSocket(socket) != nil {
		return nil, errors.New("invalid private worker configuration")
	}
	if _, e := readToken(credential); e != nil {
		return nil, e
	}
	t := &http.Transport{MaxConnsPerHost: 2, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		// Recheck the private path on every new connection, including reconnects.
		if validateSocket(socket) != nil {
			return nil, errors.New("private socket identity unavailable")
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{socket: socket, credential: credential, owner: owner, lock: lock, transport: t, http: &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.transport.CloseIdleConnections() }
func readToken(path string) (string, error) {
	f, e := openCredential(path)
	if e != nil {
		return "", errors.New("private worker credential unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 66))
	if e != nil || len(b) != 65 || b[64] != '\n' || !tokenPattern.Match(b[:64]) {
		return "", errors.New("invalid private worker credential")
	}
	return string(b[:64]), nil
}
func (c *Client) call(ctx context.Context, operation string, in, out any, budget int) error {
	// Credentials are reread so withdrawn/replaced files cannot leave a cached
	// client capability. Server-side enrollment revocation is still authoritative.
	token, e := readToken(c.credential)
	if e != nil {
		return e
	}
	b, e := json.Marshal(in)
	if e != nil {
		return errors.New("invalid worker request")
	}
	r, e := http.NewRequestWithContext(ctx, "POST", "http://unix/internal/v1/scanner/"+operation, bytes.NewReader(b))
	if e != nil {
		return errors.New("invalid worker request")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	response, e := c.http.Do(r)
	if e != nil {
		return errors.New("private worker channel unavailable")
	}
	defer response.Body.Close()
	b, e = io.ReadAll(io.LimitReader(response.Body, int64(budget)+1))
	if e != nil || len(b) > budget {
		return errors.New("worker response exceeds budget")
	}
	if response.StatusCode == 204 && operation == "claim" && len(b) == 0 {
		return ErrEmpty
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("private worker operation rejected with HTTP %d", response.StatusCode)
	}
	if strictDecode(b, out) != nil {
		return errors.New("invalid private worker response")
	}
	if strings.HasPrefix(operation, "verifier/") || strings.HasPrefix(operation, "authorizer/") || strings.HasPrefix(operation, "reconciler/") || (operation == "engine-binding" || operation == "engine-journal-binding" || operation == "engine-broker-binding") {
		canonical, e := json.Marshal(out)
		if e != nil || !bytes.Equal(bytes.TrimSpace(b), canonical) {
			return errors.New("noncanonical private verifier response")
		}
	}
	return nil
}
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var w Identity
	e := c.call(ctx, "identity", struct{}{}, &w, 8192)
	if e != nil {
		return Identity{}, e
	}
	expires, e := time.Parse(time.RFC3339, w.Expires)
	_, created := time.Parse(time.RFC3339Nano, w.Created)
	if !workerPattern.MatchString(w.ID) || w.Owner != c.owner || w.State != "active" || e != nil || created != nil || !expires.After(time.Now()) {
		return Identity{}, errors.New("worker identity binding rejected")
	}
	return w, nil
}
func (c *Client) Claim(ctx context.Context) (Lease, error) {
	var wire struct {
		LaunchProtocol    string                `json:"launch_protocol"`
		Guards            scanevidence.GuardSet `json:"guard_set"`
		WorkspaceProtocol string                `json:"workspace_protocol"`
		Schema            string                `json:"schema_version"`
		Job               Job                   `json:"job"`
		Map               source.Map            `json:"application_map"`
		Token             string                `json:"lease_token"`
		Deadline          time.Time             `json:"deadline"`
	}
	if e := c.call(ctx, "claim", struct{}{}, &wire, maxResponse); e != nil {
		return Lease{}, e
	}
	l := Lease{Job: wire.Job, Map: wire.Map, Token: wire.Token, Deadline: wire.Deadline, Guards: wire.Guards}
	if wire.Schema != "1.0" || wire.LaunchProtocol != "1.0" || wire.WorkspaceProtocol != "1.0" || c.validate(l) != nil {
		return Lease{}, errors.New("scanner claim binding rejected")
	}
	return l, nil
}
func (c *Client) validate(l Lease) error { return c.validateBinding(l, true) }

func (c *Client) validateBinding(l Lease, live bool) error {
	j := l.Job
	in := j.Input
	now := time.Now()
	expires, e := time.Parse(time.RFC3339, j.Expires)
	created, ce := time.Parse(time.RFC3339Nano, j.Created)
	if !l.Guards.Valid() || j.Schema != "1.0" || !jobPattern.MatchString(j.ID) || j.Owner != c.owner || j.LockDigest != c.lock || j.State != "running" || j.CancelRequested || j.Error != "" || j.Finished != "" || !tokenPattern.MatchString(l.Token) || e != nil || ce != nil || (live && !expires.After(now)) || !expires.After(created) || (live && !l.Deadline.After(now)) || l.Deadline.After(expires) {
		return errors.New("invalid lease")
	}
	if in.Schema != "1.0" || in.App != "app_demo" || in.Repository == "" || len(in.Repository) > 128 || !hashPattern.MatchString(in.MapDigest) || in.Mode != "repo_offline" || in.Duration < 1 || in.Duration > 120 || len(in.Tools) < 1 || len(in.Tools) > 6 || !sort.StringsAreSorted(in.Tools) {
		return errors.New("invalid input")
	}
	for i, t := range in.Tools {
		if !tools[t] || (i > 0 && in.Tools[i-1] == t) {
			return errors.New("invalid tools")
		}
	}
	request, _ := json.Marshal(struct {
		Owner string `json:"owner_id"`
		Input Input  `json:"input"`
		Lock  string `json:"tool_lock_digest"`
	}{j.Owner, in, j.LockDigest})
	m := l.Map
	m.Observed = ""
	m.Digest = ""
	mapped, _ := json.Marshal(m)
	if j.RequestDigest != source.Hash(request) || l.Map.Schema != "1.0" || l.Map.App != in.App || !strings.HasPrefix(l.Map.SourceRef, "mounted-asset:") || len(l.Map.SourceRef) <= len("mounted-asset:") || l.Map.Digest != in.MapDigest || source.Hash(mapped) != in.MapDigest || len(l.Map.Files) > 10000 {
		return errors.New("invalid source identity")
	}
	return nil
}

type leaseRequest struct {
	Job    string `json:"job_id"`
	Digest string `json:"request_digest"`
	Token  string `json:"lease_token"`
	Code   string `json:"error_code,omitempty"`
}

func (c *Client) Guard(ctx context.Context, l Lease) error {
	if c.validate(l) != nil {
		return errors.New("invalid worker lease")
	}
	var out struct {
		State string `json:"state"`
	}
	if e := c.call(ctx, "guard", leaseRequest{Job: l.Job.ID, Digest: l.Job.RequestDigest, Token: l.Token}, &out, 8192); e != nil {
		return e
	}
	if out.State != "running" {
		return errors.New("invalid guard acknowledgement")
	}
	return nil
}
func (c *Client) Fail(ctx context.Context, l Lease, code string) error {
	// Failure replay may follow the execution deadline. Verify immutable binding
	// against the original claim without treating it as renewed execution authority.
	if !jobPattern.MatchString(l.Job.ID) || l.Job.Owner != c.owner || l.Job.LockDigest != c.lock || !hashPattern.MatchString(l.Job.RequestDigest) || !tokenPattern.MatchString(l.Token) {
		return errors.New("invalid worker lease")
	}
	if code != "SCANNER_EXECUTION_FAILED" && code != "SOURCE_CAPTURE_FAILED" && code != "TOOL_UNAVAILABLE" {
		return errors.New("unsupported failure code")
	}
	var out struct {
		State   string `json:"state"`
		Cleanup bool   `json:"cleanup_required"`
	}
	if e := c.call(ctx, "fail", leaseRequest{l.Job.ID, l.Job.RequestDigest, l.Token, code}, &out, 8192); e != nil {
		return e
	}
	if out.State != "tool_error" || !out.Cleanup {
		return errors.New("invalid failure acknowledgement")
	}
	return nil
}
