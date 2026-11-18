// SPDX-License-Identifier: BUSL-1.1
package connector

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
)

var (
	ErrDraftInvalid  = errors.New("invalid desktop draft")
	ErrDraftSource   = errors.New("draft references unavailable evidence")
	ErrDraftConsent  = errors.New("draft consent unavailable")
	ErrDraftConflict = errors.New("draft submission conflicts with a retained draft")
	ErrDraftLimit    = errors.New("desktop draft storage limit reached")
	draftKeyPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	digestShape      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	handoffShape     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type DraftClaim struct {
	Claim   string   `json:"claim"`
	Kind    string   `json:"kind"`
	Sources []string `json:"source_ids"`
}

type DraftStep struct {
	Kind     string `json:"kind"`
	Text     string `json:"text"`
	Approval *bool  `json:"requires_owner_approval"`
}

type DraftDocument struct {
	Incident    string       `json:"incident_id"`
	Handoff     string       `json:"handoff_id"`
	Claims      []DraftClaim `json:"claims"`
	Limitations []string     `json:"limitations"`
	Steps       []DraftStep  `json:"proposed_steps"`
	ClientLabel string       `json:"client_label"`
}

type DraftStatus struct {
	ID    string `json:"draft_id"`
	State string `json:"state"`
}

type OwnerDraft struct {
	DraftStatus
	Created      int64         `json:"created_unix"`
	Source       string        `json:"source"`
	Connector    string        `json:"connector_id"`
	BundleDigest string        `json:"approved_bundle_digest"`
	Document     DraftDocument `json:"document"`
}

func draftText(text string, limit int) bool {
	return len(text) <= limit && utf8.ValidString(text) && strings.TrimSpace(text) != "" &&
		strings.IndexFunc(text, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError }) < 0
}

func validateDraft(d DraftDocument) bool {
	if !incidentShape.MatchString(d.Incident) || !handoffShape.MatchString(d.Handoff) ||
		!draftText(d.ClientLabel, 80) || len(d.Claims) < 1 || len(d.Claims) > 10 || len(d.Limitations) < 1 ||
		len(d.Limitations) > 8 || d.Steps == nil || len(d.Steps) > 8 {
		return false
	}
	for _, claim := range d.Claims {
		if !draftText(claim.Claim, 500) || (claim.Kind != "observation" && claim.Kind != "hypothesis") || len(claim.Sources) < 1 || len(claim.Sources) > 8 {
			return false
		}
		seen := map[string]bool{}
		for _, source := range claim.Sources {
			if !digestShape.MatchString(source) || seen[source] {
				return false
			}
			seen[source] = true
		}
	}
	for _, text := range d.Limitations {
		if !draftText(text, 320) {
			return false
		}
	}
	for _, step := range d.Steps {
		if !draftText(step.Text, 400) || step.Approval == nil ||
			(step.Kind != "investigation" && step.Kind != "verification") || (step.Kind == "verification" && !*step.Approval) {
			return false
		}
	}
	return true
}

// SubmitDraft accepts one report per explicitly approved and delivered handoff.
// Status, scope, snapshot and idempotency are decided in the write transaction.
func (r *Registry) SubmitDraft(ctx context.Context, owner, connection, key string, d DraftDocument) (DraftStatus, bool, error) {
	if !draftKeyPattern.MatchString(key) || !validateDraft(d) {
		return DraftStatus{}, false, ErrDraftInvalid
	}
	raw, _ := json.Marshal(d)
	if len(raw) > 32768 {
		return DraftStatus{}, false, ErrDraftInvalid
	}
	hash := domain.Hash(raw)
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return DraftStatus{}, false, err
	}
	defer tx.Rollback()
	var bundleRaw, bundleDigest string
	now := r.now().Unix()
	err = tx.QueryRowContext(ctx, `SELECT h.document,h.digest FROM desktop_handoffs h JOIN connector_credentials c ON c.id=h.connector AND c.owner=h.owner
 WHERE h.id=? AND h.incident=? AND h.owner=? AND h.connector=? AND h.state='delivered' AND h.allow_draft=1 AND h.expires>? AND c.state='active' AND c.expires>?`,
		d.Handoff, d.Incident, owner, connection, now, now).Scan(&bundleRaw, &bundleDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return DraftStatus{}, false, ErrDraftConsent
	}
	if err != nil {
		return DraftStatus{}, false, err
	}
	var existing DraftStatus
	var existingHandoff, existingHash string
	err = tx.QueryRowContext(ctx, `SELECT id,state,handoff,content_digest FROM desktop_analysis_drafts
 WHERE owner=? AND connector=? AND idempotency_key=?`, owner, connection, key).Scan(&existing.ID, &existing.State, &existingHandoff, &existingHash)
	if err == nil {
		if existingHandoff != d.Handoff || existingHash != hash {
			return DraftStatus{}, false, ErrDraftConflict
		}
		return existing, true, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DraftStatus{}, false, err
	}
	var bundle HandoffBundle
	if len(bundleRaw) > 16384 || domain.Hash([]byte(bundleRaw)) != bundleDigest || json.Unmarshal([]byte(bundleRaw), &bundle) != nil || bundle.Incident != d.Incident {
		return DraftStatus{}, false, ErrDraftConsent
	}
	sources := map[string]bool{}
	for _, observation := range bundle.Observations {
		sources[observation.ID] = true
	}
	for _, claim := range d.Claims {
		for _, source := range claim.Sources {
			if !sources[source] {
				return DraftStatus{}, false, ErrDraftSource
			}
		}
	}
	var used, count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM desktop_analysis_drafts WHERE handoff=?", d.Handoff).Scan(&used); err != nil {
		return DraftStatus{}, false, err
	}
	if used != 0 {
		return DraftStatus{}, false, ErrDraftConflict
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM desktop_analysis_drafts").Scan(&count); err != nil {
		return DraftStatus{}, false, err
	}
	if count >= 1024 {
		return DraftStatus{}, false, ErrDraftLimit
	}
	status := DraftStatus{ID: domain.ID(), State: "unverified"}
	if _, err = tx.ExecContext(ctx, `INSERT INTO desktop_analysis_drafts(id,owner,connector,incident,handoff,idempotency_key,document,content_digest,approved_bundle_digest,created_at,state)
 VALUES(?,?,?,?,?,?,?,?,?,?,'unverified')`, status.ID, owner, connection, d.Incident, d.Handoff, key, string(raw), hash, bundleDigest, now); err != nil {
		return DraftStatus{}, false, err
	}
	if err = store.AuditTx(tx, owner, "desktop.draft_submitted", status.ID, status.State, map[string]string{"connector_id": connection, "incident_id": d.Incident, "approved_bundle_digest": bundleDigest, "content_digest": hash}); err != nil {
		return DraftStatus{}, false, err
	}
	return status, false, tx.Commit()
}

func (r *Registry) ConnectorDraftStatus(ctx context.Context, owner, connection, draft string) (DraftStatus, error) {
	status := DraftStatus{ID: draft}
	err := r.S.DB.QueryRowContext(ctx, `SELECT d.state FROM desktop_analysis_drafts d
 JOIN connector_credentials c ON c.id=d.connector AND c.owner=d.owner
 WHERE d.id=? AND d.owner=? AND d.connector=? AND c.state='active' AND c.expires>?`, draft, owner, connection, r.now().Unix()).Scan(&status.State)
	return status, err
}

func (r *Registry) ListDrafts(ctx context.Context, owner, incident string) ([]OwnerDraft, error) {
	if !incidentShape.MatchString(incident) {
		return nil, ErrDraftInvalid
	}
	rows, err := r.S.DB.QueryContext(ctx, `SELECT id,state,created_at,connector,approved_bundle_digest,document,content_digest
 FROM desktop_analysis_drafts WHERE owner=? AND incident=? ORDER BY created_at DESC,id DESC LIMIT 20`, owner, incident)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OwnerDraft{}
	for rows.Next() {
		item := OwnerDraft{Source: "desktop_mcp"}
		var raw, digest string
		if err = rows.Scan(&item.ID, &item.State, &item.Created, &item.Connector, &item.BundleDigest, &raw, &digest); err != nil {
			return nil, err
		}
		if len(raw) > 32768 || domain.Hash([]byte(raw)) != digest || json.Unmarshal([]byte(raw), &item.Document) != nil {
			return nil, ErrDraftInvalid
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *Registry) DismissDraft(ctx context.Context, owner, id string) error {
	tx, err := r.S.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE desktop_analysis_drafts SET state='dismissed' WHERE id=? AND owner=? AND state='unverified'", id, owner)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	if err = store.AuditTx(tx, owner, "desktop.draft_dismissed", id, "dismissed", nil); err != nil {
		return err
	}
	return tx.Commit()
}
