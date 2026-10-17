// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// Change-triggered rescans (D9). An owner opts a repository in with a fixed tool
// list. CheckChanges re-reads the repository inventory and, when its application
// map digest differs from the last scanned or acknowledged digest, enqueues one
// ordinary owner scan through Enqueue (same validation, budgets and audit). It
// never claims, leases, releases or completes jobs and never touches dispatch
// slots; it defers while a job for that repository is queued or running, or
// while any of the owner's scanner cleanups is held.

const rescanPrefix = "rescan_policy/"

var ErrPolicy = errors.New("invalid rescan policy")

type RescanPolicy struct {
	Schema         string   `json:"schema_version"`
	Owner          string   `json:"owner_id"`
	Repository     string   `json:"repository_id"`
	Enabled        bool     `json:"enabled"`
	Tools          []string `json:"tool_ids"`
	Duration       int      `json:"tool_timeout_seconds"`
	BaselineDigest string   `json:"baseline_map_digest"`
	UpdatedAt      string   `json:"updated_at"`
	CheckedAt      string   `json:"last_checked_at,omitempty"`
	LastOutcome    string   `json:"last_outcome,omitempty"`
	LastJob        string   `json:"last_job_id,omitempty"`
	Retried        string   `json:"retried_map_digest,omitempty"`
}

type RescanOutcome struct {
	Owner      string `json:"owner_id"`
	Repository string `json:"repository_id"`
	Outcome    string `json:"outcome"`
	Job        string `json:"job_id,omitempty"`
}

// Refresh re-reads a repository's inventory and returns its current map digest.
type Refresh func(ctx context.Context, owner, repository string) (string, error)

func rescanKey(owner, repo string) string { return rescanPrefix + owner + "/" + repo }

func (q *Queue) loadPolicy(owner, repo string) (RescanPolicy, error) {
	v, e := q.S.Get(rescanKey(owner, repo))
	if e != nil {
		return RescanPolicy{}, e
	}
	var p RescanPolicy
	if json.Unmarshal([]byte(v), &p) != nil || p.Owner != owner || p.Repository != repo {
		return RescanPolicy{}, ErrPolicy
	}
	return p, nil
}

func (q *Queue) savePolicy(p RescanPolicy) error {
	b, _ := json.Marshal(p)
	return q.S.Set(rescanKey(p.Owner, p.Repository), string(b))
}

// RescanPolicyFor returns the owner's policy, or a disabled default.
func (q *Queue) RescanPolicyFor(owner, repo string) (RescanPolicy, error) {
	var exists int
	if e := q.S.DB.QueryRow("SELECT count(*) FROM repositories WHERE id=? AND owner=?", repo, owner).Scan(&exists); e != nil || exists == 0 {
		return RescanPolicy{}, sql.ErrNoRows
	}
	p, e := q.loadPolicy(owner, repo)
	if e == sql.ErrNoRows {
		return RescanPolicy{Schema: "1.0", Owner: owner, Repository: repo, Tools: []string{}}, nil
	}
	return p, e
}

// SetRescanPolicy records the owner's opt-in. Enabling takes the repository's
// current map digest as the baseline, so only later changes trigger scans.
func (q *Queue) SetRescanPolicy(owner, repo string, enabled bool, tools []string, duration int) (RescanPolicy, error) {
	tools = append([]string{}, tools...)
	sort.Strings(tools)
	var mapDigest, app string
	if e := q.S.DB.QueryRow("SELECT map_digest,app FROM repositories WHERE id=? AND owner=?", repo, owner).Scan(&mapDigest, &app); e != nil {
		return RescanPolicy{}, e
	}
	if enabled && !valid(Input{Schema: "1.0", App: app, Repository: repo, MapDigest: mapDigest, Mode: "repo_offline", Tools: tools, Duration: duration}) {
		return RescanPolicy{}, ErrPolicy
	}
	var count int
	prefix := rescanPrefix + owner + "/"
	if e := q.S.DB.QueryRow("SELECT count(*) FROM settings WHERE substr(key,1,length(?))=? AND key<>?", prefix, prefix, rescanKey(owner, repo)).Scan(&count); e != nil {
		return RescanPolicy{}, e
	}
	if enabled && count >= 100 {
		return RescanPolicy{}, ErrFull
	}
	p, e := q.RescanPolicyFor(owner, repo)
	if e != nil {
		return RescanPolicy{}, e
	}
	if enabled && (!p.Enabled || p.BaselineDigest == "") {
		p.BaselineDigest = mapDigest
	}
	p.Enabled, p.Tools, p.Duration, p.UpdatedAt = enabled, tools, duration, domain.Now()
	if !enabled {
		p.Tools, p.Duration = []string{}, 0
	}
	if e = q.savePolicy(p); e != nil {
		return RescanPolicy{}, e
	}
	q.S.Audit(owner, "scanner.rescan_policy", repo, map[bool]string{true: "enabled", false: "disabled"}[enabled], map[string]any{"tool_ids": p.Tools, "tool_timeout_seconds": p.Duration, "baseline_map_digest": p.BaselineDigest})
	return p, nil
}

// CheckChanges evaluates at most limit enabled policies, oldest check first,
// skipping any checked within minInterval.
func (q *Queue) CheckChanges(ctx context.Context, refresh Refresh, limit int, minInterval time.Duration) ([]RescanOutcome, error) {
	rows, e := q.S.DB.Query("SELECT value FROM settings WHERE substr(key,1,?)=? LIMIT 10000", len(rescanPrefix), rescanPrefix)
	if e != nil {
		return nil, e
	}
	policies := []RescanPolicy{}
	for rows.Next() {
		var v string
		var p RescanPolicy
		if rows.Scan(&v) == nil && json.Unmarshal([]byte(v), &p) == nil && p.Enabled {
			policies = append(policies, p)
		}
	}
	rows.Close()
	sort.Slice(policies, func(i, j int) bool { return policies[i].CheckedAt < policies[j].CheckedAt })
	now := q.now().UTC()
	out := []RescanOutcome{}
	for _, p := range policies {
		if len(out) >= limit || ctx.Err() != nil {
			break
		}
		if t, e := time.Parse(time.RFC3339Nano, p.CheckedAt); e == nil && now.Sub(t) < minInterval {
			continue
		}
		r := q.checkOne(ctx, refresh, p, now)
		out = append(out, r)
	}
	return out, nil
}

func (q *Queue) checkOne(ctx context.Context, refresh Refresh, p RescanPolicy, now time.Time) RescanOutcome {
	r := RescanOutcome{Owner: p.Owner, Repository: p.Repository}
	finish := func(outcome string) RescanOutcome {
		r.Outcome = outcome
		// Re-read so a concurrent owner change (disable, new tools) is not overwritten.
		if cur, e := q.loadPolicy(p.Owner, p.Repository); e == nil && cur.Enabled && cur.UpdatedAt == p.UpdatedAt {
			cur.CheckedAt, cur.LastOutcome = now.Format(time.RFC3339Nano), outcome
			if r.Job != "" {
				cur.LastJob = r.Job
				cur.BaselineDigest = p.BaselineDigest
				cur.Retried = p.Retried
			}
			q.savePolicy(cur)
		}
		return r
	}
	digest, e := refresh(ctx, p.Owner, p.Repository)
	if e != nil && strings.Contains(e.Error(), "budget") {
		return finish("refresh_failed_storage_budget")
	}
	if e != nil || !digestPattern.MatchString(digest) {
		return finish("refresh_failed")
	}
	retry := false
	if digest == p.BaselineDigest {
		// A rescan that failed to run (tool error or timeout) is retried once for
		// the same identity; an owner cancellation is respected.
		var state string
		if p.LastJob == "" || p.Retried == digest || q.S.DB.QueryRow("SELECT state FROM scanner_jobs WHERE id=? AND owner=?", p.LastJob, p.Owner).Scan(&state) != nil || (state != "tool_error" && state != "timeout") {
			return finish("unchanged")
		}
		retry = true
	}
	var active, held int
	if e = q.S.DB.QueryRow("SELECT count(*) FROM scanner_jobs WHERE owner=? AND repository=? AND state IN ('queued','running')", p.Owner, p.Repository).Scan(&active); e != nil {
		return finish("deferred_unavailable")
	}
	if active > 0 {
		return finish("deferred_active_job")
	}
	if e = q.S.DB.QueryRow("SELECT count(*) FROM scanner_dispatch d JOIN scanner_jobs j ON j.id=d.job WHERE j.owner=? AND d.state='cleanup_required'", p.Owner).Scan(&held); e != nil {
		return finish("deferred_unavailable")
	}
	if held > 0 {
		return finish("deferred_cleanup_held")
	}
	var app string
	if e = q.S.DB.QueryRow("SELECT app FROM repositories WHERE id=? AND owner=?", p.Repository, p.Owner).Scan(&app); e != nil {
		return finish("refresh_failed")
	}
	in := Input{Schema: "1.0", App: app, Repository: p.Repository, MapDigest: digest, Mode: "repo_offline", Tools: p.Tools, Duration: p.Duration}
	// One job per (repository, map digest, tool set): retries and restarts reuse it.
	key := "rescan:" + strings.TrimPrefix(domain.Digest(struct {
		Repository string   `json:"repository_id"`
		Digest     string   `json:"map_digest"`
		Tools      []string `json:"tool_ids"`
		Duration   int      `json:"tool_timeout_seconds"`
	}{p.Repository, digest, p.Tools, p.Duration}), "sha256:")[:48]
	if retry {
		key = "rescan-retry:" + key[7:]
	}
	job, e := q.Enqueue(p.Owner, key, in)
	switch {
	case errors.Is(e, ErrFull):
		return finish("deferred_queue_full")
	case errors.Is(e, ErrConflict):
		return finish("deferred_map_changed") // the map moved again between refresh and enqueue
	case e != nil:
		return finish("enqueue_failed")
	}
	r.Job = job.ID
	p.BaselineDigest = digest
	if retry {
		p.Retried = digest
	}
	q.S.Audit("system", "scanner.rescan_triggered", job.ID, p.Repository, map[string]any{"owner_id": p.Owner, "map_digest": digest, "tool_ids": p.Tools})
	if retry {
		return finish("retried_after_failure")
	}
	return finish("enqueued")
}
