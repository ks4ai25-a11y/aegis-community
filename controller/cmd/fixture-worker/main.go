// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/scope"
	"aegis.local/controller/internal/verify"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

var lock sync.Mutex

func main() {
	socket := env("VERIFIER_SOCKET", "/run/aegis/verifier.sock")
	os.Remove(socket)
	ln, e := net.Listen("unix", socket)
	if e != nil {
		panic(e)
	}
	os.Chmod(socket, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", run)
	s := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 50 * time.Second, MaxHeaderBytes: 8192}
	if e = s.Serve(ln); e != nil {
		panic(e)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func run(w http.ResponseWriter, r *http.Request) {
	if !lock.TryLock() {
		http.Error(w, "busy", 429)
		return
	}
	defer lock.Unlock()
	var input verify.Request
	if auth.Decode(r, &input) != nil || len(input.Job) > 128 || input.Fixture != verify.Fixture || policy.Validate(input.Policy) != nil {
		http.Error(w, "invalid fixed fixture", 400)
		return
	}
	if input.Grant != nil && scope.Validate(*input.Grant, input.Grant.Owner, time.Now()) != nil {
		http.Error(w, "scope invalid", 403)
		return
	}
	// Refuse outside the explicitly provisioned Docker sandbox. No host fallback.
	if os.Getenv("AEGIS_SANDBOX") != "internal-fixture-v1" {
		http.Error(w, "sandbox unavailable", 503)
		return
	}
	if _, e := os.Stat("/var/run/docker.sock"); e == nil {
		http.Error(w, "unsafe socket", 503)
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	if input.Grant != nil {
		expires, _ := time.Parse(time.RFC3339Nano, input.Grant.Expires)
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	root, e := os.MkdirTemp("/tmp", "aegis-fixture-")
	if e != nil {
		http.Error(w, "scratch unavailable", 503)
		return
	}
	defer os.RemoveAll(root)
	baseline := input.Policy
	baseline.Mode = "observe"
	baseline.Parent = ""
	baseline.Exclusions = []domain.Exclusion{}
	baseline.Metadata = domain.Metadata{Rationale: "Fixed Observe baseline", RequestedBy: "fixture"}
	report := domain.Report{Schema: "1.0", ID: domain.ID(), Scope: "bundled-synthetic-fixture", Level: "LEVEL_1_CONTROL_TEST", Fixture: verify.Fixture, FixtureDigest: verify.FixtureDigest(), Baseline: domain.Digest(baseline), Candidate: domain.Digest(input.Policy), Started: domain.Now(), Limitations: []string{"Covers only the listed synthetic inputs in the isolated demo.", "No production exploitability, authorization or complete remediation claim.", "Local hashes establish byte identity; a host administrator can replace local history."}}
	if input.Grant != nil {
		report.Job = input.Job
		report.ScopeGrant = input.Grant.ID
		report.ScopeDigest = domain.Digest(*input.Grant)
	}
	binary := env("CADDY_BIN", "/usr/local/bin/caddy")
	bb, e := os.ReadFile(binary)
	if e != nil {
		http.Error(w, "gateway unavailable", 503)
		return
	}
	report.Gateway = domain.Hash(bb)
	before, br, be := exercise(ctx, root, binary, baseline, 8081)
	after, ar, ae := exercise(ctx, root, binary, input.Policy, 8082)
	if be != nil || ae != nil {
		report.Overall = "INCONCLUSIVE"
	} else {
		report.Overall = verify.Classify(after[0], after[1], ar, input.Policy.Mode)
		if verify.Classify(before[0], before[1], br, "observe") != "PASS" {
			report.Overall = "FAIL"
		}
	}
	report.Checks = []domain.Check{{ID: "control-allowed", Result: check(before[0] == 200 && after[0] == 200, be, ae), BaselineStatus: before[0], CandidateStatus: after[0], Rules: []string{}}, {ID: "negative-matched-and-mode-correct", Result: report.Overall, BaselineStatus: before[1], CandidateStatus: after[1], Rules: ar, BaselineRules: br}}
	report.Completed = domain.Now()
	report.Digest = domain.Digest(report)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
func check(ok bool, es ...error) string {
	for _, e := range es {
		if e != nil {
			return "INCONCLUSIVE"
		}
	}
	if ok {
		return "PASS"
	}
	return "FAIL"
}
func exercise(ctx context.Context, root, binary string, p domain.Policy, port int) ([2]int, []string, error) {
	var statuses [2]int
	dir := filepath.Join(root, strconv.Itoa(port))
	if e := os.MkdirAll(dir, 0700); e != nil {
		return statuses, nil, e
	}
	log := filepath.Join(dir, "events.jsonl")
	cfg := policy.Render(p, "fixture-origin:8080", "127.0.0.1:"+strconv.Itoa(port), filepath.Join(dir, "admin.sock"), log)
	path := filepath.Join(dir, "Caddyfile")
	if e := os.WriteFile(path, []byte(cfg), 0600); e != nil {
		return statuses, nil, e
	}
	validation := exec.CommandContext(ctx, binary, "validate", "--config", path, "--adapter", "caddyfile")
	if e := validation.Run(); e != nil {
		return statuses, nil, e
	}
	cmd := exec.CommandContext(ctx, binary, "run", "--config", path, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	if e := cmd.Start(); e != nil {
		return statuses, nil, e
	}
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	// Readiness probes only the local listener. An HTTP health probe would
	// forward an unapproved route and spend requests outside the four-item corpus.
	if e := waitForListener(ctx, "127.0.0.1:"+strconv.Itoa(port)); e != nil {
		return statuses, nil, e
	}
	ids := [2]string{}
	for n, path := range verify.Corpus {
		req, _ := http.NewRequestWithContext(ctx, "GET", base+path, nil)
		resp, e := client.Do(req)
		if e != nil {
			return statuses, nil, e
		}
		statuses[n] = resp.StatusCode
		ids[n] = resp.Header.Get("X-Aegis-Request-ID")
		io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.Header.Get("X-Aegis-Revision") != domain.Digest(p) {
			return statuses, nil, fmt.Errorf("revision mismatch")
		}
	}
	if ids[1] == "" {
		return statuses, nil, fmt.Errorf("fixture request identity unavailable")
	}
	rules, e := waitForFixtureRules(ctx, log, ids[1])
	return statuses, rules, e
}

// A first unrelated rule is not the expected fixture evidence. Caddy drains
// sanitized telemetry asynchronously, so wait for the correlated SQLi rule or
// the bounded drain deadline. Missing evidence still classifies as failure.
func waitForFixtureRules(ctx context.Context, path, id string) ([]string, error) {
	rules := []string{}
	for n := 0; n < 20; n++ {
		if ctx.Err() != nil {
			return rules, ctx.Err()
		}
		seen := map[string]bool{}
		f, e := os.Open(path)
		if e == nil {
			scan := bufio.NewScanner(f)
			scan.Buffer(make([]byte, 8192), 8192)
			for scan.Scan() {
				var v struct {
					Request string `json:"request_id"`
					Rule    string `json:"rule_id"`
				}
				if json.Unmarshal(scan.Bytes(), &v) == nil && v.Request == id && v.Rule != "" {
					seen[v.Rule] = true
				}
			}
			e = scan.Err()
			f.Close()
			if e != nil {
				return rules, fmt.Errorf("fixture telemetry unavailable")
			}
		} else if !os.IsNotExist(e) {
			return rules, fmt.Errorf("fixture telemetry unavailable")
		}
		rules = rules[:0]
		for rule := range seen {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		if seen["942100"] {
			return rules, nil
		}
		select {
		case <-ctx.Done():
			return rules, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return rules, nil
}

// waitForListener sends no application bytes and cannot reach the fixture origin.
func waitForListener(ctx context.Context, address string) error {
	for n := 0; n < 30; n++ {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("fixture listener not ready")
}
