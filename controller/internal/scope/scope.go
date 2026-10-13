// SPDX-License-Identifier: Apache-2.0
package scope

import (
	"aegis.local/controller/internal/domain"
	"fmt"
	"time"
)

const Fixture = "crs-synthetic-sqli-pattern-v1"

type Grant struct {
	Schema      string   `json:"schema_version"`
	ID          string   `json:"scope_grant_id"`
	Owner       string   `json:"owner_id"`
	App         string   `json:"app_id"`
	Asset       string   `json:"asset_id"`
	Ownership   string   `json:"ownership_evidence"`
	Mode        string   `json:"mode"`
	Protocols   []string `json:"allowed_protocols"`
	Routes      []string `json:"allowed_routes"`
	Tests       []string `json:"allowed_tests"`
	Network     string   `json:"network_profile"`
	Addresses   []string `json:"network_addresses"`
	Concurrency int      `json:"max_concurrency"`
	Requests    int      `json:"max_requests"`
	Duration    int      `json:"max_duration_seconds"`
	Created     string   `json:"created_at"`
	Expires     string   `json:"expires_at"`
}

func Demo(owner string, expires time.Time) Grant {
	return Grant{"1.0", domain.ID(), owner, "app_demo", "bundled-waf-fixture", "Aegis-owned bundled synthetic fixture", "test_lab", []string{"http"}, []string{"/catalog", "/test-pattern"}, []string{Fixture}, "test_lab_only", []string{"fixture-origin:8080"}, 1, 4, 30, domain.Now(), expires.UTC().Format(time.RFC3339Nano)}
}
func Validate(g Grant, owner string, now time.Time) error {
	if g.Schema != "1.0" || g.ID == "" || g.Owner != owner || owner == "" || g.App != "app_demo" || g.Asset != "bundled-waf-fixture" || g.Mode != "test_lab" || g.Ownership != "Aegis-owned bundled synthetic fixture" {
		return fmt.Errorf("unsupported or unowned scope")
	}
	if g.Network != "test_lab_only" || !same(g.Addresses, []string{"fixture-origin:8080"}) || !same(g.Protocols, []string{"http"}) || !same(g.Routes, []string{"/catalog", "/test-pattern"}) || !same(g.Tests, []string{Fixture}) {
		return fmt.Errorf("target, routes or network outside bundled fixture scope")
	}
	if g.Concurrency != 1 || g.Requests != 4 || g.Duration != 30 {
		return fmt.Errorf("unsupported fixture limits")
	}
	expires, e := time.Parse(time.RFC3339Nano, g.Expires)
	if e != nil || !now.Before(expires) {
		return fmt.Errorf("scope expired")
	}
	created, e := time.Parse(time.RFC3339Nano, g.Created)
	if e != nil || created.After(now.Add(time.Second)) || expires.After(created.Add(time.Hour)) {
		return fmt.Errorf("invalid scope lifetime")
	}
	return nil
}
func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
