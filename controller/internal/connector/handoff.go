// SPDX-License-Identifier: BUSL-1.1
package connector

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
)

const handoffLifetime = 5 * time.Minute

var (
	ErrHandoffUnavailable = errors.New("handoff unavailable or expired")
	ErrHandoffChanged     = errors.New("incident preview changed")
	ErrHandoffLimit       = errors.New("too many active handoffs")
	incidentShape         = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,160}$`)
	ruleShape             = regexp.MustCompile(`^[0-9]{1,10}$`)
)

type Observation struct {
	ID       string   `json:"evidence_id"`
	Decision string   `json:"decision"`
	Rules    []string `json:"rule_ids"`
}

type HandoffBundle struct {
	Schema       string        `json:"schema_version"`
	Incident     string        `json:"incident_id"`
	Observed     string        `json:"opened_hour"`
	Severity     string        `json:"severity"`
	Observations []Observation `json:"observations"`
	Redaction    string        `json:"redaction"`
}

type HandoffPreview struct {
	Bundle HandoffBundle `json:"bundle"`
	Digest string        `json:"preview_digest"`
}

type Handoff struct {
	ID      string `json:"handoff_id"`
	Expires int64  `json:"expires_unix"`
}

// preview maps only allowlisted structured data. Text, routing fields, request
// identifiers and pseudonyms are deliberately outside this minimum export.
func preview(ctx context.Context, tx *sql.Tx, incident string) (HandoffPreview, error) {
	b := HandoffBundle{Schema: "1.0", Incident: incident, Redaction: "minimal", Observations: []Observation{}}
	if !incidentShape.MatchString(incident) {
		return HandoffPreview{}, ErrHandoffUnavailable
	}
	var opened, severity string
	if err := tx.QueryRowContext(ctx, "SELECT opened_at,severity FROM incidents WHERE id=?", incident).Scan(&opened, &severity); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return HandoffPreview{}, ErrHandoffUnavailable
		}
		return HandoffPreview{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, opened)
	if err != nil {
		return HandoffPreview{}, ErrHandoffUnavailable
	}
	b.Observed = at.UTC().Truncate(time.Hour).Format(time.RFC3339)
	switch severity {
	case "informational", "info", "low", "medium", "high", "critical":
		b.Severity = severity
	default:
		b.Severity = "unknown"
	}
	rows, err := tx.QueryContext(ctx, "SELECT e.seq,e.document FROM events e JOIN incident_events i ON e.id=i.event WHERE i.incident=? ORDER BY e.seq LIMIT 20", incident)
	if err != nil {
		return HandoffPreview{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var raw string
		if err = rows.Scan(&seq, &raw); err != nil {
			return HandoffPreview{}, err
		}
		var event struct {
			Decision string   `json:"decision"`
			Rules    []string `json:"rule_ids"`
		}
		if len(raw) > 16384 || json.Unmarshal([]byte(raw), &event) != nil {
			return HandoffPreview{}, ErrHandoffUnavailable
		}
		observation := Observation{ID: domain.Hash([]byte("aegis-desktop-observation-v1\x00" + incident + "\x00" + strconv.FormatInt(seq, 10))), Decision: "unknown", Rules: []string{}}
		switch event.Decision {
		case "allowed", "blocked", "observed", "matched", "rate_limited":
			observation.Decision = event.Decision
		}
		seen := map[string]bool{}
		for _, rule := range event.Rules {
			if ruleShape.MatchString(rule) && !seen[rule] {
				observation.Rules = append(observation.Rules, rule)
				seen[rule] = true
			}
			if len(observation.Rules) == 16 {
				break
			}
		}
		b.Observations = append(b.Observations, observation)
	}
	if err = rows.Err(); err != nil {
		return HandoffPreview{}, err
	}
	raw, _ := json.Marshal(b)
	return HandoffPreview{Bundle: b, Digest: domain.Hash(raw)}, nil
}

func (r *Registry) PreviewHandoff(ctx context.Context, incident string) (HandoffPreview, error) {
	tx, err := r.S.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return HandoffPreview{}, err
	}
	defer tx.Rollback()
	return preview(ctx, tx, incident)
}

func (r *Registry) ApproveHandoff(ctx context.Context, owner, connection, incident, digest string, allowDraft bool) (Handoff, error) {
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return Handoff{}, err
	}
	defer tx.Rollback()
	p, err := preview(ctx, tx, incident)
	if err != nil {
		return Handoff{}, err
	}
	if p.Digest != digest {
		return Handoff{}, ErrHandoffChanged
	}
	now := r.now()
	var expires int64
	err = tx.QueryRowContext(ctx, "SELECT expires FROM connector_credentials WHERE owner=? AND id=? AND state IN ('active','delivered') AND expires>?", owner, connection, now.Unix()).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Handoff{}, ErrHandoffUnavailable
	}
	if err != nil {
		return Handoff{}, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM desktop_handoffs WHERE expires<=?", now.Unix()); err != nil {
		return Handoff{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM desktop_handoffs").Scan(&count); err != nil {
		return Handoff{}, err
	}
	if count >= 256 {
		return Handoff{}, ErrHandoffLimit
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Handoff{}, err
	}
	h := Handoff{ID: hex.EncodeToString(random[:]), Expires: min(expires, now.Add(handoffLifetime).Unix())}
	document, _ := json.Marshal(p.Bundle)
	if _, err = tx.ExecContext(ctx, "INSERT INTO desktop_handoffs(id,owner,connector,incident,document,digest,expires,state,allow_draft) VALUES(?,?,?,?,?,?,?,'active',?)", h.ID, owner, connection, incident, string(document), digest, h.Expires, allowDraft); err != nil {
		return Handoff{}, err
	}
	if err = store.AuditTx(tx, owner, "desktop.handoff_approved", h.ID, "active", map[string]any{"connector_id": connection, "incident_id": incident, "preview_digest": digest, "allow_analysis_draft": allowDraft}); err != nil {
		return Handoff{}, err
	}
	return h, tx.Commit()
}

func (r *Registry) ReadHandoff(ctx context.Context, owner, connection, id string) (HandoffBundle, error) {
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return HandoffBundle{}, err
	}
	defer tx.Rollback()
	var raw, digest string
	now := r.now().Unix()
	err = tx.QueryRowContext(ctx, `SELECT h.document,h.digest FROM desktop_handoffs h JOIN connector_credentials c ON c.id=h.connector AND c.owner=h.owner
 WHERE h.id=? AND h.owner=? AND h.connector=? AND h.state='active' AND h.expires>? AND c.state='active' AND c.expires>?`, id, owner, connection, now, now).Scan(&raw, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return HandoffBundle{}, ErrHandoffUnavailable
	}
	if err != nil {
		return HandoffBundle{}, err
	}
	var bundle HandoffBundle
	if len(raw) > 16384 || domain.Hash([]byte(raw)) != digest || json.Unmarshal([]byte(raw), &bundle) != nil {
		return HandoffBundle{}, ErrHandoffUnavailable
	}
	if _, err = tx.ExecContext(ctx, "UPDATE desktop_handoffs SET state='delivered' WHERE id=?", id); err != nil {
		return HandoffBundle{}, err
	}
	if err = store.AuditTx(tx, owner, "desktop.handoff_read", id, "delivered", map[string]string{"connector_id": connection, "preview_digest": digest}); err != nil {
		return HandoffBundle{}, err
	}
	return bundle, tx.Commit()
}

func (r *Registry) RevokeHandoff(ctx context.Context, owner, id string) error {
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE desktop_handoffs SET state='revoked' WHERE owner=? AND id=? AND state IN ('active','delivered')", owner, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrHandoffUnavailable
	}
	if err = store.AuditTx(tx, owner, "desktop.handoff_revoked", id, "revoked", nil); err != nil {
		return err
	}
	return tx.Commit()
}
