// SPDX-License-Identifier: Apache-2.0
package lab

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

//go:embed tenant.go
var fixtureSource []byte

const TenantFixture = "synthetic-cross-tenant-read-v1"
const Requirement = "authenticated_subject.tenant_id == object.tenant_id"

// These are synthetic fixture identifiers, not production credentials.
var objects = map[string]string{"red-object": "org_red", "blue-object": "org_blue"}
var subjects = map[string]string{"red-user": "org_red", "blue-user": "org_blue"}

// FixtureHandler runs only trusted code bundled with Aegis. The choices represent
// seeded challenge cases, not source or commands supplied by a model.
func FixtureHandler(variant string) (http.Handler, error) {
	if variant != "vulnerable" && variant != "owner_fix" && variant != "wrong_owner_fix" && variant != "deny_all" {
		return nil, fmt.Errorf("unknown fixed fixture variant")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		subject, ok := subjects[r.Header.Get("X-Synthetic-Subject")]
		if !ok {
			w.WriteHeader(401)
			return
		}
		owner, ok := objects[r.URL.Query().Get("object")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		allowed := true
		switch variant {
		case "owner_fix":
			allowed = subject == owner
		case "wrong_owner_fix":
			allowed = subject == "org_red"
		case "deny_all":
			allowed = false
		}
		if !allowed {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"object_id": r.URL.Query().Get("object"), "tenant_id": owner, "classification": "synthetic-public-fixture-data"})
	}), nil
}

type TenantCheck struct {
	ID              string `json:"check_id"`
	BaselineStatus  int    `json:"baseline_status"`
	CandidateStatus int    `json:"candidate_status"`
	ExpectedStatus  int    `json:"expected_status"`
	Result          string `json:"result"`
}
type TenantReport struct {
	Schema             string        `json:"schema_version"`
	Fixture            string        `json:"fixture_id"`
	Scope              string        `json:"test_scope"`
	Requirement        string        `json:"declared_requirement"`
	Candidate          string        `json:"candidate_variant"`
	FixtureDigest      string        `json:"fixture_digest"`
	Checks             []TenantCheck `json:"checks"`
	BaselineReproduced bool          `json:"baseline_reproduced"`
	Overall            string        `json:"overall"`
	Tier               string        `json:"evidence_tier"`
	Limitations        []string      `json:"limitations"`
	Digest             string        `json:"report_digest"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// VerifyTenant uses HTTP outcomes and the operator-declared fixture policy. It
// never consumes the candidate's description as proof or infers a business rule.
func VerifyTenant(variant string) (TenantReport, error) {
	candidate, e := FixtureHandler(variant)
	if e != nil {
		return TenantReport{}, e
	}
	baseline, _ := FixtureHandler("vulnerable")
	before, beforeURL, e := startFixture(baseline)
	if e != nil {
		return TenantReport{}, fmt.Errorf("baseline fixture unavailable: %w", e)
	}
	defer before.Close()
	after, afterURL, e := startFixture(candidate)
	if e != nil {
		return TenantReport{}, fmt.Errorf("candidate fixture unavailable: %w", e)
	}
	defer after.Close()
	corpus := []struct {
		ID, Subject, Object string
		Expected            int
	}{
		{"red-own", "red-user", "red-object", 200}, {"blue-own", "blue-user", "blue-object", 200},
		{"red-cross", "red-user", "blue-object", 403}, {"blue-cross", "blue-user", "red-object", 403},
		{"unauthenticated", "", "red-object", 401}, {"missing-object", "red-user", "missing", 404},
	}
	r := TenantReport{Schema: "1.0", Fixture: TenantFixture, Scope: "trusted-bundled-synthetic-fixture", Requirement: Requirement, Candidate: variant, FixtureDigest: digest(map[string]any{"corpus": corpus, "implementation_sha256": digest(string(fixtureSource)), "requirement": Requirement}), Checks: []TenantCheck{}, Overall: "PASS", Tier: "T0", Limitations: []string{"Only the bundled fixture and declared tenant ownership requirement are tested.", "No production vulnerability, arbitrary patch execution, or WAF remediation claim.", "HTTP fixture is in-process loopback; disposable VM execution for customer repositories remains unavailable."}}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(base, subject, object string) (int, error) {
		req, _ := http.NewRequest("GET", base+"/object?object="+object, nil)
		req.Header.Set("X-Synthetic-Subject", subject)
		resp, e := client.Do(req)
		if e != nil {
			return 0, e
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, nil
	}
	reproduced := 0
	for _, c := range corpus {
		b, be := request(beforeURL, c.Subject, c.Object)
		a, ae := request(afterURL, c.Subject, c.Object)
		result := "PASS"
		if be != nil || ae != nil || a == 0 || b == 0 || a >= 500 || b >= 500 {
			result = "INCONCLUSIVE"
		} else if a != c.Expected {
			result = "FAIL"
		}
		if c.Expected == 403 && b == 200 {
			reproduced++
		}
		r.Checks = append(r.Checks, TenantCheck{c.ID, b, a, c.Expected, result})
		if result == "INCONCLUSIVE" {
			r.Overall = "INCONCLUSIVE"
		} else if result == "FAIL" && r.Overall != "INCONCLUSIVE" {
			r.Overall = "FAIL"
		}
	}
	r.BaselineReproduced = reproduced == 2
	if !r.BaselineReproduced {
		r.Overall = "INCONCLUSIVE"
	}
	if r.Overall == "PASS" {
		r.Tier = "T3"
	}
	r.Digest = digest(r)
	return r, nil
}

func startFixture(h http.Handler) (*http.Server, string, error) {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, "", e
	}
	server := &http.Server{Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
	go server.Serve(ln)
	return server, "http://" + ln.Addr().String(), nil
}
