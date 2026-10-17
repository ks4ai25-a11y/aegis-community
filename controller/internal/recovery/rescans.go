// SPDX-License-Identifier: BUSL-1.1
package recovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const restoredRescanPrefix = "rescan_policy/"
const maxRestoredRescans = 10000
const maxRestoredRescanBytes = 65536

func foldRescanKey(key string) string {
	var folded strings.Builder
	for _, r := range key {
		min := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < min {
				min = next
			}
		}
		folded.WriteRune(min)
	}
	return folded.String()
}

// quarantineRescan preserves preferences without replaying installation-local
// automation consent. Decode keys explicitly: encoding/json's case-insensitive
// struct matching must never let an alias or duplicate re-enable the policy.
func quarantineRescan(value, now string) (string, error) {
	if len(value) == 0 || len(value) > maxRestoredRescanBytes || !utf8.ValidString(value) {
		return "", ErrRecovery
	}
	d := json.NewDecoder(strings.NewReader(value))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return "", ErrRecovery
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return "", ErrRecovery
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return "", ErrRecovery
		}
		if strings.EqualFold(key, "enabled") || strings.EqualFold(key, "updated_at") || strings.EqualFold(key, "last_outcome") {
			continue
		}
		folded := foldRescanKey(key)
		if seen[folded] {
			return "", ErrRecovery
		}
		seen[folded] = true
		fields[key] = raw
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return "", ErrRecovery
	}
	if _, err = d.Token(); err != io.EOF {
		return "", ErrRecovery
	}
	fields["enabled"] = json.RawMessage("false")
	fields["last_outcome"] = json.RawMessage(`"restore_review_required"`)
	fields["updated_at"], err = json.Marshal(now)
	if err != nil {
		return "", ErrRecovery
	}
	b, err := json.Marshal(fields)
	if err != nil || len(b) > maxRestoredRescanBytes {
		return "", ErrRecovery
	}
	return string(b), nil
}

func disableRestoredRescans(ctx context.Context, tx *sql.Tx, now string) (int, error) {
	// Bound keys before bringing them into memory. Fetch values one at a time
	// after closing this cursor; never hold up to 10,000 full policies in memory.
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN length(CAST(key AS BLOB))<=512 THEN key ELSE NULL END FROM settings WHERE substr(key,1,?)=? ORDER BY key LIMIT ?`, len(restoredRescanPrefix), restoredRescanPrefix, maxRestoredRescans+1)
	if err != nil {
		return 0, ErrRecovery
	}
	var keys []string
	for rows.Next() {
		var key sql.NullString
		if rows.Scan(&key) != nil || !key.Valid || len(keys) >= maxRestoredRescans {
			rows.Close()
			return 0, ErrRecovery
		}
		keys = append(keys, key.String)
	}
	readErr := rows.Err()
	if rows.Close() != nil || readErr != nil {
		return 0, ErrRecovery
	}
	for _, key := range keys {
		var value sql.NullString
		if tx.QueryRowContext(ctx, "SELECT CASE WHEN length(CAST(value AS BLOB))<=? THEN value ELSE NULL END FROM settings WHERE key=?", maxRestoredRescanBytes, key).Scan(&value) != nil || !value.Valid {
			return 0, ErrRecovery
		}
		quarantined, err := quarantineRescan(value.String, now)
		if err != nil {
			return 0, err
		}
		result, err := tx.ExecContext(ctx, "UPDATE settings SET value=? WHERE key=?", quarantined, key)
		if err != nil {
			return 0, ErrRecovery
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return 0, ErrRecovery
		}
	}
	return len(keys), nil
}

// Run after the audit insert too: an ignored update, extra policy, or trigger
// that re-enables scheduling must not be committed as a quarantined restore.
func verifyRestoredRescans(ctx context.Context, tx *sql.Tx, now string, expected int) error {
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN length(CAST(value AS BLOB))<=? THEN value ELSE NULL END FROM settings WHERE substr(key,1,?)=? LIMIT ?`, maxRestoredRescanBytes, len(restoredRescanPrefix), restoredRescanPrefix, maxRestoredRescans+1)
	if err != nil {
		return ErrRecovery
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var value sql.NullString
		if rows.Scan(&value) != nil || !value.Valid || count >= expected {
			return ErrRecovery
		}
		canonical, err := quarantineRescan(value.String, now)
		if err != nil || canonical != value.String {
			return ErrRecovery
		}
		count++
	}
	if rows.Err() != nil || count != expected {
		return ErrRecovery
	}
	if rows.Close() != nil {
		return ErrRecovery
	}
	return nil
}
