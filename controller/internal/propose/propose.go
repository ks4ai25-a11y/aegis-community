// SPDX-License-Identifier: BUSL-1.1
// Package propose turns an incident's retained evidence into MitigationProposalV1
// records: complete candidate policy revisions an owner can preview in the isolated
// fixture and then explicitly approve. A proposal is data; it never activates itself.
package propose

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/store"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Schema = "1.0"

type Proposal struct {
	Schema       string        `json:"schema_version"`
	ID           string        `json:"proposal_id"`
	IncidentID   string        `json:"incident_id"`
	Site         string        `json:"site_id"`
	Kind         string        `json:"kind"`
	Priority     string        `json:"priority"`
	Title        string        `json:"title"`
	Rationale    string        `json:"rationale"`
	Impact       string        `json:"expected_impact"`
	SideEffects  []string      `json:"side_effects"`
	EvidenceRefs []string      `json:"evidence_refs"`
	Tests        []string      `json:"tests_to_run"`
	Candidate    domain.Policy `json:"candidate_policy"`
	Advisory     bool          `json:"advisory_only"`
}

// Result also lists the reasons other mitigations could not be proposed.
type Result struct {
	Proposals   []Proposal `json:"proposals"`
	NotProposed []string   `json:"not_proposed"`
}

type match struct {
	rule             int
	method, route    string
	parameter, event string
}

// Propose derives proposals for one incident against the active policy.
func Propose(s *store.Store, incident string) (Result, error) {
	res := Result{Proposals: []Proposal{}, NotProposed: []string{}}
	var notes string
	if e := s.DB.QueryRow("SELECT notes FROM incidents WHERE id=?", incident).Scan(&notes); e != nil {
		return res, e
	}
	det := map[string]any{}
	if json.Unmarshal([]byte(notes), &det) != nil || det["detector_id"] == nil {
		det["detector_id"] = "DET-01"
	}
	if det["detector_id"] == "DET-04" {
		return proposeRateLimit(s, incident, det, res)
	}
	if det["detector_id"] != "DET-01" {
		res.NotProposed = append(res.NotProposed, fmt.Sprint(det["detector_id"])+" is advisory; Community does not generate automatic mitigations for behavioural detectors.")
		return res, nil
	}
	rows, e := s.DB.Query("SELECT e.document FROM events e JOIN incident_events i ON e.id=i.event WHERE i.incident=? LIMIT 50", incident)
	if e != nil {
		return res, e
	}
	var waf []domain.Event
	site := ""
	for rows.Next() {
		var b string
		var ev domain.Event
		if rows.Scan(&b) == nil && json.Unmarshal([]byte(b), &ev) == nil {
			waf = append(waf, ev)
			site = ev.Site
		}
	}
	rows.Close()
	if len(waf) == 0 {
		res.NotProposed = append(res.NotProposed, "Linked evidence has aged out of retention.")
		return res, nil
	}
	active, digest, e := s.Active()
	if e != nil {
		return res, e
	}
	mode, exclusions, demo := active.Mode, active.Exclusions, site == "site_demo"
	if reg, ok := active.FindSite(site); ok {
		mode, exclusions = reg.Mode, reg.Exclusions
	} else if !demo {
		res.NotProposed = append(res.NotProposed, site+" is no longer registered in the active policy.")
		return res, nil
	}
	// Pair each WAF record with the access record of the same request for method and route.
	var matches []match
	refs := []string{}
	for _, ev := range waf {
		refs = append(refs, ev.ID)
		if ev.Source != "coraza" || len(ev.Rules) == 0 {
			continue
		}
		rule, _ := strconv.Atoi(ev.Rules[0])
		var b string
		if s.DB.QueryRow("SELECT document FROM events WHERE request=? AND json_extract(document,'$.source')='caddy-access' LIMIT 1", ev.Request).Scan(&b) != nil {
			continue
		}
		var acc domain.Event
		if json.Unmarshal([]byte(b), &acc) != nil {
			continue
		}
		matches = append(matches, match{rule, acc.Method, acc.Route, strings.TrimPrefix(ev.Target, "ARGS:"), ev.ID})
	}
	if len(refs) > 20 {
		refs = refs[:20]
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].event < matches[j].event })

	base := func(rationale string) domain.Policy {
		p := clone(active)
		p.Parent = digest
		p.Metadata = domain.Metadata{Rationale: rationale, RequestedBy: "local-owner"}
		return p
	}
	// 1. Narrow exclusion for a likely false positive.
	excluded := false
	for _, m := range matches {
		if m.parameter == "" {
			continue
		}
		x := domain.Exclusion{RuleID: m.rule, Method: m.method, Path: m.route, Parameter: m.parameter}
		if contains(exclusions, x) {
			res.NotProposed = append(res.NotProposed, fmt.Sprintf("An exclusion for rule %d on %s %s parameter %s already exists.", m.rule, m.method, m.route, m.parameter))
			excluded = true
			break
		}
		p := base(fmt.Sprintf("Exclude parameter %s from CRS rule %d on %s %s for 30 days (proposed from incident)", m.parameter, m.rule, m.method, m.route))
		// Proposed exclusions are temporary by default; the owner can renew them.
		x.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
		setExclusions(&p, site, append(append([]domain.Exclusion{}, exclusions...), x))
		if e := policy.Validate(p); e != nil {
			res.NotProposed = append(res.NotProposed, fmt.Sprintf("Exclusion for rule %d on %s %s cannot be expressed safely: %s.", m.rule, m.method, m.route, e))
			excluded = true
			break
		}
		res.Proposals = append(res.Proposals, finish(Proposal{IncidentID: incident, Site: site, Kind: "exclusion", Priority: "P3",
			Title:        fmt.Sprintf("Exclude %s from rule %d on %s %s", m.parameter, m.rule, m.method, m.route),
			Rationale:    "Use only if the matching requests are legitimate. The exclusion removes this one parameter from this one rule on this exact route; every other rule still inspects it.",
			Impact:       "Requests whose only match was this rule on this parameter stop raising this observation and are not blocked by it in Protect.",
			SideEffects:  []string{"A real attack carried in this parameter would no longer be detected by this rule.", "The isolated fixture preview fails if the exclusion would remove the bundled negative control.", "It expires after 30 days; Aegis then removes it automatically if the stricter revision passes the fixture."},
			EvidenceRefs: refs, Tests: []string{"Validate and preview the candidate: the pinned gateway must accept it and the bundled benign and negative controls must still pass.", "Replay the legitimate request that triggered the incident in a staging copy of the application."},
			Candidate: p}))
		excluded = true
		break
	}
	if !excluded {
		res.NotProposed = append(res.NotProposed, "No matched parameter name was recorded, so no parameter-scoped exclusion can be proposed.")
	}
	// 2. Enable Protect for the site.
	if mode == "observe" {
		p := base("Enable Protect for " + site + " after reviewing this incident")
		setMode(&p, site, "protect")
		if e := policy.Validate(p); e == nil {
			res.Proposals = append(res.Proposals, finish(Proposal{IncidentID: incident, Site: site, Kind: "protect", Priority: "P2",
				Title:        "Enable Protect for " + site,
				Rationale:    "If the matching requests are not legitimate traffic, Protect lets CRS deny requests whose anomaly score reaches the configured threshold.",
				Impact:       "Requests scoring at or above the threshold receive 403 instead of reaching the origin.",
				SideEffects:  []string{"Legitimate requests that trigger CRS rules will be blocked; review false positives first.", "Protect is a request-level control and does not fix application vulnerabilities."},
				EvidenceRefs: refs, Tests: []string{"Validate and preview the candidate in the isolated fixture.", "After activation, confirm benign traffic on the site's main routes still succeeds."},
				Candidate: p}))
		}
	} else {
		res.NotProposed = append(res.NotProposed, site+" is already in Protect.")
	}
	return res, nil
}

func finish(p Proposal) Proposal {
	p.Schema, p.Advisory = Schema, true
	p.ID = domain.Digest(map[string]any{"incident": p.IncidentID, "kind": p.Kind, "candidate": p.Candidate})
	return p
}

func clone(p domain.Policy) domain.Policy {
	b, _ := json.Marshal(p)
	var out domain.Policy
	json.Unmarshal(b, &out)
	return out
}

func contains(xs []domain.Exclusion, x domain.Exclusion) bool {
	for _, y := range xs {
		if y.RuleID == x.RuleID && y.Method == x.Method && y.Path == x.Path && y.Parameter == x.Parameter {
			return true
		}
	}
	return false
}

func setExclusions(p *domain.Policy, site string, xs []domain.Exclusion) {
	if site == "site_demo" {
		p.Exclusions = xs
		return
	}
	for i := range p.Sites {
		if p.Sites[i].ID == site {
			p.Sites[i].Exclusions = xs
		}
	}
}

func setMode(p *domain.Policy, site, mode string) {
	if site == "site_demo" {
		p.Mode = mode
		return
	}
	for i := range p.Sites {
		if p.Sites[i].ID == site {
			p.Sites[i].Mode = mode
		}
	}
}

// proposeRateLimit answers a request-burst incident on a registered site with an
// owner-approvable per-client limit. The demo site has no rate-limit support.
func proposeRateLimit(s *store.Store, incident string, det map[string]any, res Result) (Result, error) {
	site, _ := det["site_id"].(string)
	active, digest, e := s.Active()
	if e != nil {
		return res, e
	}
	reg, ok := active.FindSite(site)
	if !ok {
		res.NotProposed = append(res.NotProposed, "Rate limits apply to registered sites only.")
		return res, nil
	}
	if reg.RateLimit != nil {
		res.NotProposed = append(res.NotProposed, fmt.Sprintf("%s already limits clients to %d requests per %d s.", site, reg.RateLimit.Requests, reg.RateLimit.WindowSeconds))
		return res, nil
	}
	refs := []string{}
	rows, e := s.DB.Query("SELECT event FROM incident_events WHERE incident=? LIMIT 20", incident)
	if e == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				refs = append(refs, id)
			}
		}
		rows.Close()
	}
	p := clone(active)
	p.Parent = digest
	p.Metadata = domain.Metadata{Rationale: "Limit each client of " + site + " to 600 requests per minute (proposed from a burst incident)", RequestedBy: "local-owner"}
	for i := range p.Sites {
		if p.Sites[i].ID == site {
			p.Sites[i].RateLimit = &domain.RateLimit{Requests: 600, WindowSeconds: 60}
		}
	}
	if e := policy.Validate(p); e != nil {
		res.NotProposed = append(res.NotProposed, "A rate limit cannot be expressed safely: "+e.Error())
		return res, nil
	}
	res.Proposals = append(res.Proposals, finish(Proposal{IncidentID: incident, Site: site, Kind: "rate_limit", Priority: "P2",
		Title:        "Limit each client of " + site + " to 600 requests per minute",
		Rationale:    "One client exceeded the burst threshold. A per-client limit returns 429 to excess requests before they reach the WAF or the origin.",
		Impact:       "Clients sending more than 600 requests in a minute receive 429 until the window passes.",
		SideEffects:  []string{"Clients behind one shared address (NAT, corporate proxy, CDN without trusted proxy support) share the limit.", "Legitimate batch jobs or load tests above this rate are slowed."},
		EvidenceRefs: refs, Tests: []string{"Validate and preview the candidate in the isolated fixture.", "Confirm normal browsing and API clients stay well below the limit."},
		Candidate: p}))
	return res, nil
}
