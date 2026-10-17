//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package recovery

import (
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/store"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rescanPreference = `{"schema_version":"1.0","owner_id":"owner","repository_id":"repo","enabled":true,"tool_ids":["bandit","gitleaks"],"tool_timeout_seconds":120,"baseline_map_digest":"retained-baseline","updated_at":"2026-10-15T00:00:00Z","last_outcome":"queued"}`

func TestQuarantineRescanCollapsesEverySchedulingAlias(t *testing.T) {
	for _, extra := range []string{``, `,"ENABLED":true`, `,"Enabled":false,"enabled":true`, `,"\u0065nabled":true`, `,"last_outcome":"running","LAST_OUTCOME":"queued"`, `,"enabled":null`, `,"enabled":[true]`} {
		value := strings.TrimSuffix(rescanPreference, "}") + extra + "}"
		got, err := quarantineRescan(value, "2026-10-17T00:00:00Z")
		if err != nil {
			t.Fatal("scheduling aliases could not be safely disabled", err)
		}
		var policy scanqueue.RescanPolicy
		if json.Unmarshal([]byte(got), &policy) != nil || policy.Enabled || policy.LastOutcome != "restore_review_required" || policy.UpdatedAt != "2026-10-17T00:00:00Z" || strings.Join(policy.Tools, ",") != "bandit,gitleaks" || policy.Duration != 120 || policy.BaselineDigest != "retained-baseline" {
			t.Fatal("quarantine lost preferences or retained scheduling consent")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(got), &fields) != nil {
			t.Fatal("quarantine output invalid")
		}
		for key := range fields {
			if strings.EqualFold(key, "enabled") && key != "enabled" {
				t.Fatal("noncanonical scheduling alias survived")
			}
		}
	}
}

func TestQuarantineRescanRefusesMalformedOrAmbiguousPreferences(t *testing.T) {
	for _, value := range []string{"", "null", "[]", "true", "{", rescanPreference + "{}", strings.TrimSuffix(rescanPreference, "}") + `,"tool_ids":["syft"]}`, strings.TrimSuffix(rescanPreference, "}") + `,"TOOL_IDS":["syft"]}`, strings.TrimSuffix(rescanPreference, "}") + `,"tool_idſ":["syft"]}`, strings.Repeat(" ", maxRestoredRescanBytes+1), "{\"enabled\":true,\"x\":\"" + string([]byte{0xff}) + "\"}"} {
		if _, err := quarantineRescan(value, "2026-10-17T00:00:00Z"); err != ErrRecovery {
			t.Fatal("malformed preference accepted")
		}
	}
}

func TestRestoreDisablesRescansPreservesPreferencesAndSkipsScheduler(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	key := restoredRescanPrefix + "owner/repo"
	if err := s.Set(key, strings.TrimSuffix(rescanPreference, "}")+`,"ENABLED":true}`); err != nil {
		t.Fatal(err)
	}
	// A LIKE underscore wildcard must not sweep unrelated settings into this
	// restore operation. Only the exact rescan_policy/ prefix is recognized.
	if err := s.Set("rescanXpolicy/untouched", "private-unrelated-canary"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("rescanYpolicy/untouched", rescanPreference); err != nil {
		t.Fatal(err)
	}
	bundle, receipt := makeBundle(t, c, parent)
	before, err := os.ReadFile(filepath.Join(bundle, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "restored-rescans")
	if _, err = Restore(context.Background(), c, bundle, destination, receipt.Bundle); err != nil {
		t.Fatal(err)
	}
	restored, err := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	q := &scanqueue.Queue{S: restored}
	policy, err := q.RescanPolicyFor("owner", "repo")
	if err != nil || policy.Enabled || policy.LastOutcome != "restore_review_required" || policy.Duration != 120 || strings.Join(policy.Tools, ",") != "bandit,gitleaks" || policy.BaselineDigest != "retained-baseline" {
		t.Fatal("restored consent or preference mismatch", err)
	}
	called := false
	outcomes, err := q.CheckChanges(context.Background(), func(context.Context, string, string) (string, error) {
		called = true
		return "changed-baseline", nil
	}, 10, 0)
	if err != nil || called || len(outcomes) != 0 {
		t.Fatal("restored preference caused automatic repository refresh")
	}
	var count int
	if err = restored.DB.QueryRow(`SELECT json_extract(document,'$.data.rescan_policies_quarantined') FROM audit WHERE json_extract(document,'$.action')='recovery.authority_invalidated' ORDER BY seq DESC LIMIT 1`).Scan(&count); err != nil || count != 1 {
		t.Fatal("rescan quarantine count not audited", err)
	}
	if value, err := restored.Get("rescanXpolicy/untouched"); err != nil || value != "private-unrelated-canary" {
		t.Fatal("unrelated setting changed")
	}
	if value, err := restored.Get("rescanYpolicy/untouched"); err != nil || value != rescanPreference {
		t.Fatal("near-match preference was altered instead of excluded")
	}
	var state string
	if err = restored.DB.QueryRow("SELECT state FROM scanner_dispatch").Scan(&state); err != nil || state != "cleanup_required" || restored.VerifyAuditContext(context.Background()) != nil {
		t.Fatal("restore lost cleanup hold or audit integrity", err)
	}
	after, err := os.ReadFile(filepath.Join(bundle, "state.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restore changed the source bundle")
	}
}

func TestRestoreRescanFailuresNeverPublishDestination(t *testing.T) {
	for _, kind := range []string{"malformed", "oversize", "ignored-update", "audit-reenable", "audit-extra"} {
		t.Run(kind, func(t *testing.T) {
			c, s, parent := fixture(t)
			seedAuthorities(t, s)
			value := rescanPreference
			if kind == "malformed" {
				value = "{"
			}
			if kind == "oversize" {
				value = strings.Repeat(" ", maxRestoredRescanBytes+1)
			}
			if err := s.Set(restoredRescanPrefix+"owner/repo", value); err != nil {
				t.Fatal(err)
			}
			var trigger string
			switch kind {
			case "ignored-update":
				trigger = `CREATE TRIGGER refuse_rescan_update BEFORE UPDATE ON settings WHEN OLD.key='rescan_policy/owner/repo' BEGIN SELECT RAISE(IGNORE); END`
			case "audit-reenable":
				trigger = `CREATE TRIGGER rescan_after_audit AFTER INSERT ON audit WHEN json_extract(NEW.document,'$.action')='recovery.authority_invalidated' BEGIN UPDATE settings SET value=json_set(value,'$.enabled',json('true')) WHERE key='rescan_policy/owner/repo'; END`
			case "audit-extra":
				trigger = `CREATE TRIGGER rescan_after_audit AFTER INSERT ON audit WHEN json_extract(NEW.document,'$.action')='recovery.authority_invalidated' BEGIN INSERT INTO settings(key,value) SELECT 'rescan_policy/extra/repo',value FROM settings WHERE key='rescan_policy/owner/repo'; END`
			}
			if trigger != "" {
				if _, err := s.DB.Exec(trigger); err != nil {
					t.Fatal(err)
				}
			}
			bundle, receipt := makeBundle(t, c, parent)
			destination := filepath.Join(parent, "refused-rescan-restore")
			if _, err := Restore(context.Background(), c, bundle, destination, receipt.Bundle); err != ErrRecovery {
				t.Fatal("unsafe rescan restore accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("failed restore published a destination")
			}
			if current, err := s.Get(restoredRescanPrefix + "owner/repo"); err != nil || current != value {
				t.Fatal("failed restore changed source preferences")
			}
		})
	}
}

func TestRestoreRescanCountBoundDoesNotIgnoreExcessPolicies(t *testing.T) {
	_, s, _ := fixture(t)
	if _, err := s.DB.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?) INSERT INTO settings(key,value) SELECT 'rescan_policy/owner/'||x,'{"enabled":true}' FROM n`, maxRestoredRescans+1); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = disableRestoredRescans(context.Background(), tx, "2026-10-17T00:00:00Z"); err != ErrRecovery {
		t.Fatal("excess policies silently escaped invalidation")
	}
}

func TestVersionThirteenRescanPreferenceRequiresNewConsent(t *testing.T) {
	c, s, parent := fixture(t)
	seedAuthorities(t, s)
	removeAllocationSchema(t, s)
	for _, statement := range []string{"DROP TABLE scanner_authorizers", "DROP TABLE connector_credentials", "DELETE FROM migrations WHERE version>=14"} {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Set(restoredRescanPrefix+"owner/repo", rescanPreference); err != nil {
		t.Fatal(err)
	}
	bundle, receipt := makeBundle(t, c, parent)
	destination := filepath.Join(parent, "legacy-rescan-restore")
	if _, err := Restore(context.Background(), c, bundle, destination, receipt.Bundle); err != nil {
		t.Fatal(err)
	}
	restored, err := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	var version int
	if err = restored.DB.QueryRow("SELECT max(version) FROM migrations").Scan(&version); err != nil || version != 13 {
		t.Fatal("consent invalidation upgraded legacy storage", err)
	}
	p, err := (&scanqueue.Queue{S: restored}).RescanPolicyFor("owner", "repo")
	if err != nil || p.Enabled || p.BaselineDigest != "retained-baseline" || len(p.Tools) != 2 || p.Duration != 120 {
		t.Fatal("legacy preference lost or automatically enabled", err)
	}
}

func TestRescanPreferenceAndAuthorityRollbackTogetherOnAuditFailure(t *testing.T) {
	_, s, _ := fixture(t)
	seedAuthorities(t, s)
	key := restoredRescanPrefix + "owner/repo"
	if err := s.Set(key, rescanPreference); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER refuse_recovery_audit BEFORE INSERT ON audit WHEN json_extract(NEW.document,'$.action')='recovery.authority_invalidated' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if invalidate(context.Background(), s, "synthetic-bundle") != ErrRecovery {
		t.Fatal("unaudited preference invalidation succeeded")
	}
	if value, err := s.Get(key); err != nil || value != rescanPreference {
		t.Fatal("failed audit committed preference changes")
	}
	var sessions, workers int
	if err := s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("failed audit committed session invalidation", err)
	}
	if err := s.DB.QueryRow("SELECT count(*) FROM scanner_workers WHERE state='active'").Scan(&workers); err != nil || workers != 1 || s.VerifyAuditContext(context.Background()) != nil {
		t.Fatal("failed audit committed authority invalidation", err)
	}
}
