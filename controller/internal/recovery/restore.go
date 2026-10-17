// SPDX-License-Identifier: Apache-2.0
package recovery

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Restore(ctx context.Context, c Config, bundle, destination, confirmation string) (out Receipt, err error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	source, m, e := verified(ctx, c, bundle)
	if e != nil {
		return out, e
	}
	defer source.close()
	if confirmation != m.Digest {
		return out, ErrRecovery
	}
	relative, e := filepath.Rel(bundle, destination)
	if e != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return out, ErrRecovery
	}
	target, e := openPrivate(destination, true)
	if e != nil {
		return out, e
	}
	defer target.close()
	done := false
	preserve := false
	defer func() {
		if !done && !preserve {
			os.RemoveAll(destination)
		}
	}()
	for _, directory := range []string{"data", "gateway", "tools"} {
		if target.root.Mkdir(directory, 0700) != nil {
			return out, ErrRecovery
		}
	}
	if target.write("data/"+store.RestorePending, []byte("recovery-v1\n")) != nil {
		return out, ErrRecovery
	}
	for _, file := range []struct {
		Source, Target string
		Expected       Artifact
		Max            int64
	}{{"state.db", "data/aegis.db", m.Document.Database, maxDatabase}, {"active.Caddyfile", "gateway/active.Caddyfile", m.Document.Gateway, 65536}, {"scanners.lock.json", "tools/scanners.lock.json", m.Document.Tools, 65536}} {
		actual, e := hashOrCopy(ctx, source, file.Source, target, file.Target, file.Max)
		if e != nil || actual != file.Expected {
			return out, ErrRecovery
		}
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(destination, "data/aegis.db"), RawQuery: "mode=rw&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"}).String()
	database, e := sql.Open("sqlite", uri)
	var state *store.Store
	if e == nil {
		database.SetMaxOpenConns(1)
		state = &store.Store{DB: database, Path: filepath.Join(destination, "data/aegis.db")}
	}
	if e != nil {
		return out, ErrRecovery
	}
	if e = invalidate(ctx, state, m.Digest); e != nil {
		state.DB.Close()
		return out, e
	}
	if state.VerifyAuditContext(ctx) != nil {
		state.DB.Close()
		return out, ErrRecovery
	}
	if _, e = state.DB.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		state.DB.Close()
		return out, ErrRecovery
	}
	if state.DB.Close() != nil {
		return out, ErrRecovery
	}
	// Sync every finished file and directory before publishing the completion receipt.
	for _, name := range []string{"data/aegis.db", "gateway/active.Caddyfile", "tools/scanners.lock.json", "data", "gateway", "tools"} {
		f, e := target.root.Open(name)
		if e != nil {
			return out, ErrRecovery
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return out, ErrRecovery
		}
	}
	installed, e := hashOrCopy(ctx, target, "data/aegis.db", nil, "", maxDatabase)
	if e != nil {
		return out, e
	}
	out = receipt(m, "restored_offline")
	out.RestoredDatabase = installed.Digest
	out.Authorities = true
	out.CleanupHeld = true
	data, _ := json.Marshal(out)
	if target.write("data/.restore-complete.json", append(data, '\n')) != nil {
		return Receipt{}, ErrRecovery
	}
	if target.write("recovery.json", append(data, '\n')) != nil {
		return Receipt{}, ErrRecovery
	}
	preserve = true
	if target.root.Remove("data/"+store.RestorePending) != nil {
		return Receipt{}, ErrRecovery
	}
	dataDir, e := target.root.Open("data")
	if e != nil {
		return Receipt{}, ErrRecovery
	}
	e = dataDir.Sync()
	dataDir.Close()
	if e != nil || target.sync() != nil {
		return Receipt{}, ErrRecovery
	}
	done = true
	return out, nil
}
func invalidate(ctx context.Context, s *store.Store, bundle string) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrRecovery
	}
	defer tx.Rollback()
	statements := []string{
		"DELETE FROM sessions",
		"DELETE FROM idempotency",
		"DELETE FROM invites",
		"DELETE FROM consents",
		"DELETE FROM handoffs",
		"UPDATE connections SET state='revoked',expires=0,epoch=epoch+1",
		"UPDATE drafts SET state='RESTORE_REVIEW_REQUIRED'",
		"UPDATE scope_grants SET state='revoked' WHERE state!='revoked'",
		"UPDATE scanner_workers SET state='revoked' WHERE state='active'",
		"UPDATE scanner_verifiers SET state='revoked' WHERE state='active'",
		"UPDATE scanner_dispatch SET state='cleanup_required',lease_until=0",
		"UPDATE jobs SET state='cancelled' WHERE state IN ('queued','running')",
		"DELETE FROM settings WHERE key LIKE 'preview:%' OR key='apply_journal' OR key='scanner_engine_binding' OR key='scanner_engine_journal_binding' OR key='scanner_engine_broker_binding'",
		"UPDATE policies SET state='RESTORE_REVIEW_REQUIRED' WHERE state IN ('PENDING_APPROVAL','APPLYING')",
	}
	for _, statement := range statements {
		if _, e = tx.ExecContext(ctx, statement); e != nil {
			return ErrRecovery
		}
	}
	// Version-13 bundles have no authorizer table. Do not upgrade a captured
	// database during offline restore; revoke the new role when it is present
	// in a verified version-14 bundle, and preserve older bundle compatibility.
	var version int
	if e = tx.QueryRowContext(ctx, "SELECT max(version) FROM migrations").Scan(&version); e != nil {
		return ErrRecovery
	}
	if version < 13 || version > 16 {
		return ErrRecovery
	}
	if version >= 14 {
		if _, e = tx.ExecContext(ctx, "UPDATE scanner_authorizers SET state='revoked' WHERE state='active'"); e != nil {
			return ErrRecovery
		}
	}
	// Version 15 adds connector credentials; restored assistants must re-pair.
	if version >= 15 {
		if _, e = tx.ExecContext(ctx, "UPDATE connector_credentials SET state='revoked' WHERE state='active'"); e != nil {
			return ErrRecovery
		}
	}
	// Revocation closes open generations through migration-016 triggers. Keep
	// every pending mutation and original scope; restore is never cleanup.
	if version >= 16 {
		if _, e = tx.ExecContext(ctx, "UPDATE scanner_mutation_bindings SET state='revoked' WHERE state='active'"); e != nil {
			return ErrRecovery
		}
		if _, e = tx.ExecContext(ctx, "UPDATE scanner_allocation_generations SET state='closed',closed_at=? WHERE state='open'", domain.Now()); e != nil {
			return ErrRecovery
		}
	}
	now := domain.Now()
	if _, e = tx.ExecContext(ctx, "UPDATE research_jobs SET state='cancelled',cancel_requested=1,lease_token='',worker='',lease_until=0,finished_at=?,error_code='RESTORE_AUTHORITY_INVALIDATED' WHERE state IN ('queued','running')", now); e != nil {
		return ErrRecovery
	}
	if _, e = tx.ExecContext(ctx, "UPDATE scanner_jobs SET state='cancelled',cancel_requested=1,finished_at=?,error_code='RESTORE_AUTHORITY_INVALIDATED' WHERE state IN ('queued','running')", now); e != nil {
		return ErrRecovery
	}
	rescans, e := disableRestoredRescans(ctx, tx, now)
	if e != nil {
		return ErrRecovery
	}
	if e = store.AuditTx(tx, "local-restore", "recovery.authority_invalidated", bundle, "QUARANTINED", map[string]any{"schema_version": "1.0", "live_activated": false, "scanner_cleanup_holds_preserved": true, "rescan_policies_quarantined": rescans, "automatic_rescan_reenable_required": true}); e != nil {
		return ErrRecovery
	}
	if verifyRestoredRescans(ctx, tx, now, rescans) != nil {
		return ErrRecovery
	}
	if e = tx.Commit(); e != nil {
		return ErrRecovery
	}
	return nil
}
