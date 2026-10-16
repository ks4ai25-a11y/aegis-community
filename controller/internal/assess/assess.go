// SPDX-License-Identifier: Apache-2.0
// Package assess builds a bounded, sanitized incident dossier and produces an
// IncidentAssessmentV1, either deterministically or with an optional local model.
// Assessments are advice: they never change policy, and the deterministic path
// works with no model, network or account at all.
package assess

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const Schema = "1.0"

// Dossier is everything an assessor may see. It contains only records that the
// gateway sanitizer and ingest already bounded; none of it is an instruction.
type Dossier struct {
	Schema   string          `json:"schema_version"`
	Incident IncidentFacts   `json:"incident"`
	Evidence []EvidenceFacts `json:"evidence"`
	Site     SiteFacts       `json:"site"`
	Related  int             `json:"related_open_incidents_24h"`
}
type IncidentFacts struct {
	ID         string         `json:"incident_id"`
	Summary    string         `json:"summary"`
	OpenedAt   string         `json:"opened_at"`
	Severity   string         `json:"severity"`
	Confidence string         `json:"confidence"`
	Detector   map[string]any `json:"detector"`
}
type EvidenceFacts struct {
	Ref      string   `json:"ref"`
	At       string   `json:"observed_at"`
	Source   string   `json:"source"`
	Method   string   `json:"method,omitempty"`
	Route    string   `json:"route_template,omitempty"`
	Status   *int     `json:"http_status,omitempty"`
	Rules    []string `json:"rule_ids"`
	Decision string   `json:"decision"`
	Client   string   `json:"client_key,omitempty"`
}
type SiteFacts struct {
	ID         string       `json:"site_id"`
	Mode       string       `json:"mode"`
	CRS        domain.CRS   `json:"crs"`
	Exclusions int          `json:"exclusions"`
	Routes     []RouteFacts `json:"top_routes"`
}
type RouteFacts struct {
	Method string `json:"method"`
	Route  string `json:"route_template"`
	Count  int    `json:"requests_retained"`
}

type Hypothesis struct {
	Statement  string   `json:"statement"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence_refs"`
}
type Recommendation struct {
	Action string `json:"action"`
	Kind   string `json:"kind"`
	Risk   string `json:"risk_of_action"`
}
type Provenance struct {
	Assessor      string `json:"assessor"`
	Model         string `json:"model,omitempty"`
	DossierDigest string `json:"dossier_digest"`
	GeneratedAt   string `json:"generated_at"`
	Fallback      string `json:"fallback_reason,omitempty"`
}

// Assessment is IncidentAssessmentV1 from the v4 manual (E5).
type Assessment struct {
	Schema          string           `json:"schema_version"`
	IncidentID      string           `json:"incident_id"`
	ObservedFacts   []string         `json:"observed_facts"`
	Hypotheses      []Hypothesis     `json:"hypotheses"`
	Uncertainties   []string         `json:"uncertainties"`
	Recommendations []Recommendation `json:"recommendations"`
	Tests           []string         `json:"recommended_tests"`
	Provenance      Provenance       `json:"provenance"`
	Advisory        bool             `json:"advisory_only"`
}

// Build assembles the dossier for one incident from local storage.
func Build(s *store.Store, id string) (Dossier, error) {
	d := Dossier{Schema: Schema, Evidence: []EvidenceFacts{}}
	var notes, site string
	e := s.DB.QueryRow("SELECT id,summary,opened_at,severity,confidence,notes FROM incidents WHERE id=?", id).Scan(&d.Incident.ID, &d.Incident.Summary, &d.Incident.OpenedAt, &d.Incident.Severity, &d.Incident.Confidence, &notes)
	if e != nil {
		return d, e
	}
	d.Incident.Detector = map[string]any{}
	if json.Unmarshal([]byte(notes), &d.Incident.Detector) != nil || d.Incident.Detector["detector_id"] == nil {
		d.Incident.Detector = map[string]any{"detector_id": "DET-01", "detector_version": "legacy"}
	}
	rows, e := s.DB.Query("SELECT e.document FROM events e JOIN incident_events i ON e.id=i.event WHERE i.incident=? ORDER BY e.seq LIMIT 50", id)
	if e != nil {
		return d, e
	}
	for rows.Next() {
		var b string
		if rows.Scan(&b) != nil {
			continue
		}
		var ev domain.Event
		if json.Unmarshal([]byte(b), &ev) != nil {
			continue
		}
		site = ev.Site
		d.Evidence = append(d.Evidence, EvidenceFacts{ev.ID, ev.At, ev.Source, ev.Method, ev.Route, ev.Status, ev.Rules, ev.Decision, ev.ClientKey})
	}
	rows.Close()
	if s, ok := d.Incident.Detector["site_id"].(string); ok && s != "" {
		site = s
	}
	if site == "" {
		site = "site_demo"
	}
	p, _, e := s.Active()
	if e != nil {
		return d, e
	}
	d.Site = SiteFacts{ID: site, Mode: p.Mode, CRS: p.CRS, Exclusions: len(p.Exclusions)}
	if reg, ok := p.FindSite(site); ok {
		d.Site.Mode, d.Site.CRS, d.Site.Exclusions = reg.Mode, reg.CRS, len(reg.Exclusions)
	}
	routes, e := s.DB.Query("SELECT json_extract(document,'$.method'),json_extract(document,'$.route_template'),count(*) n FROM events WHERE json_extract(document,'$.source')='caddy-access' AND json_extract(document,'$.site_id')=? GROUP BY 1,2 ORDER BY n DESC LIMIT 20", site)
	if e == nil {
		for routes.Next() {
			var r RouteFacts
			var m, t sql.NullString
			if routes.Scan(&m, &t, &r.Count) == nil {
				r.Method, r.Route = m.String, t.String
				d.Site.Routes = append(d.Site.Routes, r)
			}
		}
		routes.Close()
	}
	s.DB.QueryRow("SELECT count(*) FROM incidents WHERE state='open' AND id<>? AND opened_at>=strftime('%Y-%m-%dT%H:%M:%fZ',?,'-1 day')", id, d.Incident.OpenedAt).Scan(&d.Related)
	return d, nil
}

func clean(v string, n int) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if len([]rune(v)) > n {
		v = string([]rune(v)[:n])
	}
	return v
}

// Deterministic produces a reproducible assessment from the dossier alone.
func Deterministic(d Dossier) Assessment {
	a := Assessment{Schema: Schema, IncidentID: d.Incident.ID, Advisory: true, Hypotheses: []Hypothesis{}, Recommendations: []Recommendation{}}
	det, _ := d.Incident.Detector["detector_id"].(string)
	refs := []string{}
	rules := map[string]bool{}
	clients := map[string]bool{}
	statuses := map[int]int{}
	blocked := 0
	for _, e := range d.Evidence {
		refs = append(refs, e.Ref)
		for _, r := range e.Rules {
			rules[r] = true
		}
		if e.Client != "" {
			clients[e.Client] = true
		}
		if e.Status != nil {
			statuses[*e.Status/100*100]++
		}
		if e.Decision == "blocked_waf" {
			blocked++
		}
	}
	if len(refs) > 10 {
		refs = refs[:10]
	}
	ruleList := keys(rules)
	a.ObservedFacts = append(a.ObservedFacts,
		fmt.Sprintf("%s raised this incident on %s at %s.", det, d.Site.ID, d.Incident.OpenedAt),
		fmt.Sprintf("%s linked; %s.", plural(len(d.Evidence), "retained evidence record is", "retained evidence records are"), plural(len(clients), "distinct pseudonymous client appears", "distinct pseudonymous clients appear")),
		fmt.Sprintf("The site is in %s mode with CRS blocking paranoia %d and anomaly threshold %d.", d.Site.Mode, d.Site.CRS.Blocking, d.Site.CRS.Threshold))
	if len(ruleList) > 0 {
		a.ObservedFacts = append(a.ObservedFacts, "CRS rules matched: "+strings.Join(ruleList, ", ")+".")
	}
	if blocked > 0 {
		a.ObservedFacts = append(a.ObservedFacts, plural(blocked, "linked request was", "linked requests were")+" denied by the WAF.")
	}
	if d.Related > 0 {
		a.ObservedFacts = append(a.ObservedFacts, plural(d.Related, "other incident", "other incidents")+" opened in the preceding 24 hours.")
	}
	a.Uncertainties = []string{
		"Request bodies, query values and client addresses are not retained, so payload intent cannot be confirmed.",
		"A detector or rule match does not establish that exploitation succeeded or that the application is vulnerable.",
		"Application authorization and tenant ownership were not assessed.",
	}
	switch det {
	case "DET-01":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"Requests contained input resembling an attack pattern recognised by CRS rules " + strings.Join(ruleList, ", ") + ".", "medium", refs})
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"The match is a false positive caused by legitimate input on this route.", "low", refs})
		if d.Site.Mode == "observe" {
			a.Recommendations = append(a.Recommendations, Recommendation{"Review the matching routes; if they carry only legitimate traffic, add a narrowly scoped exclusion before enabling Protect.", "exclusion", "low"})
			a.Recommendations = append(a.Recommendations, Recommendation{"Preview Protect for this site in the isolated fixture and enable it once false positives are understood.", "protect", "medium"})
		} else {
			a.Recommendations = append(a.Recommendations, Recommendation{"Confirm that legitimate requests on these routes still succeed after the block.", "investigate", "low"})
		}
		a.Tests = append(a.Tests, "Replay the bundled synthetic SQL-injection control and a benign control against a candidate policy in the isolated fixture.")
	case "DET-02":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"One client is discovering content by requesting many unknown paths.", "medium", refs}, Hypothesis{"A crawler, monitoring tool or shared NAT produced the pattern.", "medium", refs})
		a.Recommendations = append(a.Recommendations, Recommendation{"Check whether any discovered path returned success; review those routes for unintended exposure.", "investigate", "low"})
	case "DET-03":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"Credentials or tokens are being guessed against an authentication or authorization boundary.", "medium", refs}, Hypothesis{"A misconfigured client is retrying with expired credentials.", "medium", refs})
		a.Recommendations = append(a.Recommendations, Recommendation{"Confirm the application enforces account lockout or throttling for these routes.", "investigate", "low"})
	case "DET-04":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"An automated client is sending a high request rate.", "high", refs})
		a.Recommendations = append(a.Recommendations, Recommendation{"Determine whether the client is expected (load test, batch job) before considering a rate limit.", "investigate", "low"})
	case "DET-05":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"The origin is failing or being overloaded.", "medium", refs}, Hypothesis{"Probing triggered unhandled errors in the application.", "low", refs})
		a.Recommendations = append(a.Recommendations, Recommendation{"Check origin health and recent deployments before treating this as attack impact.", "investigate", "low"})
	case "DET-06":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"An administrative or diagnostic route is reachable through the gateway.", "high", refs})
		a.Recommendations = append(a.Recommendations, Recommendation{"Confirm this route requires authentication and is meant to be public; otherwise restrict it at the application.", "investigate", "low"})
	case "DET-07":
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"The active revision no longer produces the expected outcome for the bundled synthetic controls.", "high", refs}, Hypothesis{"The gateway or demo origin is degraded and the canary result is not representative.", "medium", refs})
		a.Recommendations = append(a.Recommendations, Recommendation{"Check gateway health and the active revision, then roll back to the last revision whose canary passed if the regression is confirmed.", "rollback", "medium"})
		a.Tests = append(a.Tests, "Re-run the canary from the Overview page after rollback or repair.")
	default:
		a.Hypotheses = append(a.Hypotheses, Hypothesis{"The detector observed a pattern that requires manual review.", "low", refs})
	}
	if len(d.Evidence) == 0 {
		a.Uncertainties = append(a.Uncertainties, "Linked evidence has aged out of retention; this assessment relies on the incident summary only.")
	}
	return a
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
