// SPDX-License-Identifier: BUSL-1.1
// Package engineobserve reads one explicitly selected TLS scanner engine using
// only an observer identity. Absence is an observation, not cleanup release.
package engineobserve

import (
	"aegis.local/alpha/enginetls"
	"aegis.local/source"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var ErrUnconfirmed = errors.New("independent scanner engine absence unconfirmed")

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var namePattern = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)
var engineIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

type Config struct {
	// Endpoint must use the original broker's logical Unix socket path, viewed
	// through the observer's own explicitly provisioned mount/opaque TLS relay.
	Endpoint, IdentityDirectory, ExpectedEngine string
	BrokerCertificatePEM                        []byte
}

type Target struct {
	Name, ID string
}

type Reader struct {
	endpoint, expected, broker string
	identity                   *enginetls.Identity
	transport                  *http.Transport
	client                     *http.Client
	closed                     atomic.Bool
}

// Open reads private observer credentials and a public broker certificate. It
// does not contact the engine, read ambient Docker settings, or create state.
func Open(c Config) (*Reader, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "unix" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || !filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path || u.Path == "/" || strings.ContainsAny(u.Path, "\x00\r\n") || c.Endpoint != "unix://"+u.Path || !digestPattern.MatchString(c.ExpectedEngine) {
		return nil, ErrUnconfirmed
	}
	identity, err := enginetls.Load(c.IdentityDirectory, enginetls.Observer)
	if err != nil {
		return nil, ErrUnconfirmed
	}
	broker, err := identity.BrokerCertificateDigest(c.BrokerCertificatePEM)
	if err != nil {
		return nil, ErrUnconfirmed
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{Protocols: protocols, Proxy: nil, TLSClientConfig: identity.TLS, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 65536, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", u.Path)
	}}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Reader{endpoint: c.Endpoint, expected: c.ExpectedEngine, broker: broker, identity: identity, transport: tr, client: client}, nil
}

func (r *Reader) Close() {
	if r != nil && !r.closed.Swap(true) {
		r.transport.CloseIdleConnections()
	}
}

func (r *Reader) get(ctx context.Context, path string, status int) ([]byte, error) {
	got, b, err := r.read(ctx, path)
	if err != nil || got != status {
		return nil, ErrUnconfirmed
	}
	return b, nil
}

// read performs one bounded TLS 1.3 GET and returns its status and body.
func (r *Reader) read(ctx context.Context, path string) (int, []byte, error) {
	if r.closed.Load() || r.identity.Check() != nil {
		return 0, nil, ErrUnconfirmed
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+enginetls.ServerName+"/v1.55"+path, nil)
	if err != nil {
		return 0, nil, ErrUnconfirmed
	}
	response, err := r.client.Do(req)
	if err != nil {
		return 0, nil, ErrUnconfirmed
	}
	defer response.Body.Close()
	if response.ProtoMajor != 1 || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.Uncompressed || response.Header.Get("Content-Encoding") != "" {
		return 0, nil, ErrUnconfirmed
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(b) == 0 || len(b) > 65536 || r.closed.Load() || r.identity.Check() != nil || ctx.Err() != nil {
		return 0, nil, ErrUnconfirmed
	}
	return response.StatusCode, b, nil
}

// objectFields accepts exactly one bounded JSON object, refusing ambiguous
// root keys (including aliases). Unknown engine metadata is not authority.
func objectFields(b []byte) (map[string]json.RawMessage, error) {
	if len(b) == 0 || len(b) > 65536 || !utf8.Valid(b) {
		return nil, ErrUnconfirmed
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrUnconfirmed
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[strings.ToLower(key)] {
			return nil, ErrUnconfirmed
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrUnconfirmed
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrUnconfirmed
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrUnconfirmed
	}
	return fields, nil
}

func (r *Reader) sameEngine(ctx context.Context) error {
	b, err := r.get(ctx, "/info", http.StatusOK)
	if err != nil {
		return err
	}
	fields, err := objectFields(b)
	if err != nil {
		return err
	}
	var id, osType, arch string
	if json.Unmarshal(fields["ID"], &id) != nil || json.Unmarshal(fields["OSType"], &osType) != nil || json.Unmarshal(fields["Architecture"], &arch) != nil || !engineIDPattern.MatchString(id) || osType != "linux" || (arch != "amd64" && arch != "x86_64" && arch != "arm64" && arch != "aarch64") {
		return ErrUnconfirmed
	}
	if source.Hash([]byte("aegis-scanner-mtls-engine-v1\n"+r.endpoint+"\n"+id+"\n"+r.broker)) != r.expected {
		return ErrUnconfirmed
	}
	return nil
}

// VerifyAbsent reads both the full engine ID and the exact retained name for
// every supplied allocation, bracketed by original engine identity checks.
// The caller must independently authenticate complete allocation membership,
// close/fence all mutations, settle obligations and hold the original registry
// barrier before using this observation in a cleanup-release transaction.
func (r *Reader) VerifyAbsent(ctx context.Context, targets []Target) error {
	if r == nil || ctx == nil || r.closed.Load() || len(targets) == 0 || len(targets) > 6 {
		return ErrUnconfirmed
	}
	targets = append([]Target(nil), targets...)
	names, ids := map[string]bool{}, map[string]bool{}
	for _, target := range targets {
		// An empty ID is a launch whose create was never admitted: only its
		// exact name can be observed absent.
		if !namePattern.MatchString(target.Name) || (target.ID != "" && !idPattern.MatchString(target.ID)) || names[target.Name] || (target.ID != "" && ids[target.ID]) {
			return ErrUnconfirmed
		}
		names[target.Name] = true
		if target.ID != "" {
			ids[target.ID] = true
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.sameEngine(ctx) != nil {
		return ErrUnconfirmed
	}
	for _, target := range targets {
		for _, exact := range []string{target.ID, target.Name} {
			if exact == "" {
				continue
			}
			b, err := r.get(ctx, "/containers/"+exact+"/json", http.StatusNotFound)
			if err != nil {
				return ErrUnconfirmed
			}
			// Only the daemon's own not-found answer counts; a router 404
			// ("page not found") is not evidence of absence (QA R4-7).
			fields, err := objectFields(b)
			var message string
			if err != nil || len(fields) != 1 || json.Unmarshal(fields["message"], &message) != nil || !strings.HasPrefix(message, "No such container") {
				return ErrUnconfirmed
			}
		}
	}
	return r.sameEngine(ctx)
}

// ContainerState is one exact observation of a retained allocation name.
type ContainerState struct {
	Present bool
	ID      string
	Started bool
}

// getEither is get for an exact read whose only acceptable answers are the
// object (200) or the daemon's own "No such container" (404).
func (r *Reader) getEither(ctx context.Context, path string) (map[string]json.RawMessage, bool, error) {
	status, b, err := r.read(ctx, path)
	if err != nil || status != http.StatusOK && status != http.StatusNotFound {
		return nil, false, ErrUnconfirmed
	}
	if status == http.StatusOK {
		fields, err := objectFields(b)
		if err != nil {
			return nil, false, ErrUnconfirmed
		}
		return fields, true, nil
	}
	fields, err := objectFields(b)
	var message string
	if err != nil || len(fields) != 1 || json.Unmarshal(fields["message"], &message) != nil || !strings.HasPrefix(message, "No such container") {
		return nil, false, ErrUnconfirmed
	}
	return nil, false, nil
}

// Inspect observes one exact retained name and, when known, its exact engine
// ID, bracketed by original engine identity checks (ADR 057 crash repair).
// Present requires the name to resolve to exactly one container whose name
// and ID match; a known ID must agree. Absent requires the daemon's own
// not-found answer for every exact identity. Anything else is unconfirmed.
// A two-request read can race a concurrent write; the caller must hold the
// quarantine fence that excludes engine writes for this allocation.
func (r *Reader) Inspect(ctx context.Context, target Target) (ContainerState, error) {
	if r == nil || ctx == nil || r.closed.Load() || !namePattern.MatchString(target.Name) || (target.ID != "" && !idPattern.MatchString(target.ID)) {
		return ContainerState{}, ErrUnconfirmed
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.sameEngine(ctx) != nil {
		return ContainerState{}, ErrUnconfirmed
	}
	read := func(exact string) (ContainerState, error) {
		fields, present, err := r.getEither(ctx, "/containers/"+exact+"/json")
		if err != nil || !present {
			return ContainerState{}, err
		}
		var id, name string
		var state map[string]json.RawMessage
		if json.Unmarshal(fields["Id"], &id) != nil || json.Unmarshal(fields["Name"], &name) != nil || json.Unmarshal(fields["State"], &state) != nil || !idPattern.MatchString(id) || name != "/"+target.Name {
			return ContainerState{}, ErrUnconfirmed
		}
		var status, startedAt string
		if json.Unmarshal(state["Status"], &status) != nil || json.Unmarshal(state["StartedAt"], &startedAt) != nil {
			return ContainerState{}, ErrUnconfirmed
		}
		started, err := time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			return ContainerState{}, ErrUnconfirmed
		}
		out := ContainerState{Present: true, ID: id}
		switch {
		case status == "created" && started.Year() <= 1:
		case (status == "running" || status == "exited" || status == "paused" || status == "restarting") && started.Year() > 1:
			out.Started = true
		default:
			// Removing, dead or contradictory state is not positive evidence.
			return ContainerState{}, ErrUnconfirmed
		}
		return out, nil
	}
	byName, err := read(target.Name)
	if err != nil {
		return ContainerState{}, ErrUnconfirmed
	}
	if target.ID != "" {
		byID, err := read(target.ID)
		if err != nil || byID != byName || byName.Present && byName.ID != target.ID {
			return ContainerState{}, ErrUnconfirmed
		}
	}
	if r.sameEngine(ctx) != nil {
		return ContainerState{}, ErrUnconfirmed
	}
	return byName, nil
}
