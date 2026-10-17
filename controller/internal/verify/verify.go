// SPDX-License-Identifier: BUSL-1.1
package verify

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scope"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const Fixture = "crs-synthetic-sqli-pattern-v1"

var Corpus = []string{"/catalog?query=ordinary", "/test-pattern?query=1%27%20OR%20%271%27%3D%271"}

func FixtureDigest() string {
	return domain.Digest(map[string]any{"id": Fixture, "requests": Corpus, "max_requests": 4, "timeout_seconds": 30})
}

type Request struct {
	Fixture string        `json:"fixture_id"`
	Policy  domain.Policy `json:"policy"`
	Grant   *scope.Grant  `json:"scope_grant,omitempty"`
	Job     string        `json:"job_id,omitempty"`
}
type Client struct{ Socket string }

func (c Client) Run(ctx context.Context, p domain.Policy) (domain.Report, error) {
	return c.run(ctx, p, nil, "")
}
func (c Client) RunScoped(ctx context.Context, p domain.Policy, g scope.Grant) (domain.Report, error) {
	if e := scope.Validate(g, g.Owner, time.Now()); e != nil {
		return domain.Report{}, fmt.Errorf("verifier scope invalid")
	}
	return c.run(ctx, p, &g, "")
}
func (c Client) RunJob(ctx context.Context, p domain.Policy, g scope.Grant, job string) (domain.Report, error) {
	if e := scope.Validate(g, g.Owner, time.Now()); e != nil {
		return domain.Report{}, e
	}
	return c.run(ctx, p, &g, job)
}
func (c Client) run(ctx context.Context, p domain.Policy, g *scope.Grant, job string) (domain.Report, error) {
	b, _ := json.Marshal(Request{Fixture: Fixture, Policy: p, Grant: g, Job: job})
	h := &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/run", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, e := h.Do(req)
	if e != nil {
		return domain.Report{}, fmt.Errorf("isolated verifier unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return domain.Report{}, fmt.Errorf("verifier refused job")
	}
	var report domain.Report
	e = auth.Decode(&http.Request{Body: resp.Body, Header: http.Header{"Content-Type": []string{resp.Header.Get("Content-Type")}}}, &report)
	if e != nil {
		return report, e
	}
	digest := report.Digest
	report.Digest = ""
	if domain.Digest(report) != digest {
		return report, fmt.Errorf("report integrity mismatch")
	}
	report.Digest = digest
	if report.Candidate != domain.Digest(p) || report.FixtureDigest != FixtureDigest() {
		return report, fmt.Errorf("tested identity mismatch")
	}
	if g != nil && (report.ScopeGrant != g.ID || report.ScopeDigest != domain.Digest(*g) || report.Job != job) {
		return report, fmt.Errorf("scope report identity mismatch")
	}
	if e = ValidateReport(report, p); e != nil {
		return report, e
	}
	return report, nil
}
func Classify(control, negative int, rules []string, mode string) string {
	if control == 0 || negative == 0 || control >= 500 || negative >= 500 {
		return "INCONCLUSIVE"
	}
	if control != 200 {
		return "FAIL"
	}
	matched := false
	for _, rule := range rules {
		if rule == "942100" {
			matched = true
		}
	}
	if !matched {
		return "FAIL"
	}
	if mode == "protect" && negative == 403 {
		return "PASS"
	}
	if mode == "observe" && negative == 200 {
		return "PASS"
	}
	return "FAIL"
}

// ValidateReport independently checks the fixed assertions, not just the worker's summary.
func ValidateReport(r domain.Report, p domain.Policy) error {
	if r.Schema != "1.0" || r.Fixture != Fixture || r.FixtureDigest != FixtureDigest() || r.Candidate != domain.Digest(p) || len(r.Checks) != 2 {
		return fmt.Errorf("incomplete verifier report identity or controls")
	}
	baseline := p
	baseline.Mode = "observe"
	baseline.Parent = ""
	baseline.Exclusions = []domain.Exclusion{}
	baseline.Metadata = domain.Metadata{Rationale: "Fixed Observe baseline", RequestedBy: "fixture"}
	if r.Baseline != domain.Digest(baseline) {
		return fmt.Errorf("unexpected baseline identity")
	}
	if r.Overall != "PASS" && r.Overall != "FAIL" && r.Overall != "INCONCLUSIVE" {
		return fmt.Errorf("unknown verification outcome")
	}
	control, negative := r.Checks[0], r.Checks[1]
	if control.ID != "control-allowed" || negative.ID != "negative-matched-and-mode-correct" {
		return fmt.Errorf("expected assertions missing")
	}
	if r.Overall == "PASS" {
		if control.Result != "PASS" || negative.Result != "PASS" || control.BaselineStatus != 200 || Classify(control.CandidateStatus, negative.CandidateStatus, negative.Rules, p.Mode) != "PASS" || Classify(control.BaselineStatus, negative.BaselineStatus, negative.BaselineRules, "observe") != "PASS" {
			return fmt.Errorf("report summary contradicts control evidence")
		}
	}
	return nil
}
