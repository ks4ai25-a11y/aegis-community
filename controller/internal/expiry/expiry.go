// SPDX-License-Identifier: Apache-2.0
// Package expiry removes exclusions whose owner-approved expiry has passed. The
// stricter revision still has to pass the isolated fixture before activation; if it
// does not, the exclusion stays and an incident asks the owner to decide.
package expiry

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"time"
)

const Actor = "system:expiry"

type Worker struct {
	S      *store.Store
	Verify func(context.Context, domain.Policy) (domain.Report, error)
	Apply  func(context.Context, domain.Policy, string) error
	Now    func() time.Time
}

type Outcome struct {
	Changed  bool
	Applied  string
	Incident string
	Err      error
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Tick performs at most one expiry revision.
func (w *Worker) Tick(ctx context.Context) Outcome {
	active, digest, e := w.S.Active()
	if e != nil {
		return Outcome{Err: e}
	}
	c, changed := policy.Expired(active, w.now())
	if !changed {
		return Outcome{}
	}
	c.Parent = digest
	c.Metadata = domain.Metadata{Rationale: "Automatic removal of expired exclusions", RequestedBy: Actor}
	if e = policy.Validate(c); e != nil {
		return Outcome{Changed: true, Err: e}
	}
	d := domain.Digest(c)
	var owner string
	if e = w.S.DB.QueryRow("SELECT id FROM owners LIMIT 1").Scan(&owner); e != nil {
		return Outcome{Changed: true, Err: e} // no owner yet: nothing can be reviewed
	}
	report, e := w.Verify(ctx, c)
	if e == nil {
		e = w.S.SaveReport(owner, report)
	}
	if e != nil || report.Overall != "PASS" {
		return Outcome{Changed: true, Incident: w.incident(digest, report.Overall), Err: e}
	}
	b, _ := json.Marshal(c)
	if _, e = w.S.DB.Exec("INSERT OR IGNORE INTO policies VALUES(?,?,?,?,?,?)", d, digest, string(b), "PENDING_APPROVAL", domain.Now(), Actor); e != nil {
		return Outcome{Changed: true, Err: e}
	}
	if e = w.Apply(ctx, c, Actor); e != nil {
		return Outcome{Changed: true, Err: e}
	}
	return Outcome{Changed: true, Applied: d}
}

func (w *Worker) incident(revision, result string) string {
	if result == "" {
		result = "unavailable"
	}
	id := domain.Hash([]byte("expiry|" + revision + "|" + w.now().UTC().Format("2006-01-02")))
	notes, _ := json.Marshal(map[string]any{"detector_id": "DET-07", "detector_version": "1.0", "site_id": "site_demo", "window_seconds": 0, "threshold": 1, "observed": 1, "response": "record_only",
		"assumption": "An exclusion expired, but the stricter revision did not pass the isolated fixture (" + result + "). The exclusion remains active until the owner reviews it."})
	w.S.DB.Exec("INSERT OR IGNORE INTO incidents(id,summary,opened_at,state,severity,confidence,notes) VALUES(?,?,?,'open','medium','high',?)", id, "Expired exclusion could not be removed safely", domain.Now(), string(notes))
	w.S.Audit(Actor, "policy.expiry_held", id, result, map[string]string{"revision": revision})
	return id
}
