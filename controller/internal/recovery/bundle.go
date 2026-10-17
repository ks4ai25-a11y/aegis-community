// SPDX-License-Identifier: Apache-2.0
package recovery

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/store"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var ErrRecovery = errors.New("recovery bundle refused or incomplete")

const maxDatabase int64 = 512 << 20
const profile = "demo-http-v1"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$`)

type Config struct{ Database, Gateway, ToolLock string }
type Artifact struct {
	Bytes  int64  `json:"byte_count"`
	Digest string `json:"sha256"`
}
type Manifest struct {
	Schema        string   `json:"schema_version"`
	Product       string   `json:"product_version"`
	Profile       string   `json:"deployment_profile"`
	Created       string   `json:"created_at"`
	SchemaVersion int      `json:"database_schema_version"`
	Policy        string   `json:"policy_digest"`
	Database      Artifact `json:"database"`
	Gateway       Artifact `json:"gateway_configuration"`
	Tools         Artifact `json:"scanner_lock"`
}
type Envelope struct {
	Digest   string   `json:"bundle_digest"`
	Document Manifest `json:"document"`
}
type Receipt struct {
	Schema           string `json:"schema_version"`
	Status           string `json:"status"`
	Bundle           string `json:"bundle_digest"`
	Policy           string `json:"policy_digest"`
	Lock             string `json:"tool_lock_digest"`
	Integrity        bool   `json:"integrity_verified"`
	Authorities      bool   `json:"restored_authorities_invalidated"`
	CleanupHeld      bool   `json:"scanner_cleanup_holds_preserved"`
	Activated        bool   `json:"live_activated"`
	RestoreVerified  bool   `json:"application_restore_verified"`
	Signature        bool   `json:"publisher_signature_verified"`
	RestoredDatabase string `json:"restored_database_digest,omitempty"`
}

func receipt(m Envelope, status string) Receipt {
	return Receipt{Schema: "1.0", Status: status, Bundle: m.Digest, Policy: m.Document.Policy, Lock: m.Document.Tools.Digest, Integrity: true}
}
func gatewayBytes(p domain.Policy) []byte {
	return []byte(policy.Render(p, "demo-origin:8080", ":8080", "/run/gateway/admin.sock", "/var/log/aegis/events.jsonl"))
}
func lockBytes(ctx context.Context, path string) ([]byte, error) {
	data, e := readOwned(ctx, path, 65536, false)
	if e != nil {
		return nil, ErrRecovery
	}
	var lock struct {
		Schema string `json:"schema_version"`
		Tools  []struct{ ID, Version, Image string }
	}
	if json.Unmarshal(data, &lock) != nil || lock.Schema != "1.0" || len(lock.Tools) != 6 {
		return nil, ErrRecovery
	}
	expected := map[string]bool{"semgrep_ce": true, "osv_v2": true, "trivy": true, "syft": true, "gitleaks": true, "bandit": true}
	for _, tool := range lock.Tools {
		if !expected[tool.ID] || len(tool.Version) == 0 || len(tool.Version) > 64 || !imagePattern.MatchString(tool.Image) {
			return nil, ErrRecovery
		}
		delete(expected, tool.ID)
	}
	if len(expected) != 0 {
		return nil, ErrRecovery
	}
	return data, nil
}
func databaseContext(ctx context.Context, path string) (domain.Policy, int, error) {
	s, e := store.OpenSnapshotSource(ctx, path)
	if e != nil {
		return domain.Policy{}, 0, ErrRecovery
	}
	defer s.DB.Close()
	if s.VerifyAuditContext(ctx) != nil {
		return domain.Policy{}, 0, ErrRecovery
	}
	var version int
	if s.DB.QueryRowContext(ctx, "SELECT max(version) FROM migrations").Scan(&version) != nil || (version < 13 || version > 16) {
		return domain.Policy{}, 0, ErrRecovery
	}
	var authorizers int
	if s.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='scanner_authorizers'").Scan(&authorizers) != nil || version == 13 && authorizers != 0 || version >= 14 && authorizers != 1 {
		return domain.Policy{}, 0, ErrRecovery
	}
	for _, name := range []string{"scanner_mutation_bindings", "scanner_allocation_generations", "scanner_mutation_intents"} {
		var tables int
		if s.DB.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&tables) != nil || (version >= 16 && tables != 1) || (version < 16 && tables != 0) {
			return domain.Policy{}, 0, ErrRecovery
		}
	}
	var integrity string
	if s.DB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity) != nil || integrity != "ok" {
		return domain.Policy{}, 0, ErrRecovery
	}
	foreign, e := s.DB.QueryContext(ctx, "PRAGMA foreign_key_check")
	if e != nil {
		return domain.Policy{}, 0, ErrRecovery
	}
	invalid := foreign.Next()
	fe := foreign.Err()
	foreign.Close()
	if invalid || fe != nil {
		return domain.Policy{}, 0, ErrRecovery
	}
	p, d, e := s.Active()
	if e != nil || policy.Validate(p) != nil || domain.Digest(p) != d {
		return p, 0, ErrRecovery
	}
	var journal string
	e = s.DB.QueryRowContext(ctx, "SELECT coalesce((SELECT value FROM settings WHERE key='apply_journal'),'')").Scan(&journal)
	var pending int
	if e != nil || journal != "" || s.DB.QueryRowContext(ctx, "SELECT count(*) FROM policies WHERE state='APPLYING'").Scan(&pending) != nil || pending != 0 {
		return p, 0, ErrRecovery
	}
	return p, version, nil
}
func Create(ctx context.Context, c Config, destination string) (out Receipt, err error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	source, e := store.OpenSnapshotSource(ctx, c.Database)
	if e != nil {
		return out, ErrRecovery
	}
	defer source.DB.Close()
	trusted, e := lockBytes(ctx, c.ToolLock)
	if e != nil {
		return out, e
	}
	root, e := openPrivate(destination, true)
	if e != nil {
		return out, e
	}
	defer root.close()
	done := false
	defer func() {
		if !done {
			os.RemoveAll(destination)
		}
	}()
	if source.Backup(ctx, filepath.Join(destination, "state.db")) != nil {
		return out, ErrRecovery
	}
	p, version, e := databaseContext(ctx, filepath.Join(destination, "state.db"))
	if e != nil {
		return out, e
	}
	gateway, e := readOwned(ctx, c.Gateway, 65536, false)
	if e != nil || !bytes.Equal(gateway, gatewayBytes(p)) {
		return out, ErrRecovery
	}
	if root.write("active.Caddyfile", gateway) != nil || root.write("scanners.lock.json", trusted) != nil {
		return out, ErrRecovery
	}
	database, e := hashOrCopy(ctx, root, "state.db", nil, "", maxDatabase)
	if e != nil {
		return out, e
	}
	m := Envelope{Document: Manifest{Schema: "1.0", Product: domain.Version, Profile: profile, Created: domain.Now(), SchemaVersion: version, Policy: domain.Digest(p), Database: database, Gateway: Artifact{int64(len(gateway)), domain.Hash(gateway)}, Tools: Artifact{int64(len(trusted)), domain.Hash(trusted)}}}
	m.Digest = domain.Digest(m.Document)
	data, _ := json.Marshal(m)
	if root.write("manifest.json", append(data, '\n')) != nil {
		return out, ErrRecovery
	}
	done = true
	return receipt(m, "bundle_created"), nil
}
func verified(ctx context.Context, c Config, path string) (*private, Envelope, error) {
	var empty Envelope
	root, e := openPrivate(path, false)
	if e != nil {
		return nil, empty, e
	}
	valid := false
	defer func() {
		if !valid {
			root.close()
		}
	}()
	entries, e := os.ReadDir(path)
	if e != nil || len(entries) != 5 {
		return nil, empty, ErrRecovery
	}
	names := map[string]bool{".lock": true, "state.db": true, "active.Caddyfile": true, "scanners.lock.json": true, "manifest.json": true}
	for _, entry := range entries {
		if !names[entry.Name()] {
			return nil, empty, ErrRecovery
		}
	}
	data, e := readOwned(ctx, filepath.Join(path, "manifest.json"), 8192, true)
	if e != nil {
		return nil, empty, e
	}
	var m Envelope
	if json.Unmarshal(data, &m) != nil {
		return nil, empty, ErrRecovery
	}
	canonical, _ := json.Marshal(m)
	if !bytes.Equal(bytes.TrimSpace(data), canonical) || m.Digest != domain.Digest(m.Document) || !digestPattern.MatchString(m.Digest) {
		return nil, empty, ErrRecovery
	}
	d := m.Document
	if d.Schema != "1.0" || d.Product != domain.Version || d.Profile != profile || (d.SchemaVersion < 13 || d.SchemaVersion > 16) || !digestPattern.MatchString(d.Policy) {
		return nil, empty, ErrRecovery
	}
	stamp, e := time.Parse(time.RFC3339Nano, d.Created)
	if e != nil || stamp.After(time.Now().Add(2*time.Second)) {
		return nil, empty, ErrRecovery
	}
	for _, file := range []struct {
		Name     string
		Expected Artifact
		Max      int64
	}{{"state.db", d.Database, maxDatabase}, {"active.Caddyfile", d.Gateway, 65536}, {"scanners.lock.json", d.Tools, 65536}} {
		if !digestPattern.MatchString(file.Expected.Digest) || file.Expected.Bytes < 1 || file.Expected.Bytes > file.Max {
			return nil, empty, ErrRecovery
		}
		actual, e := hashOrCopy(ctx, root, file.Name, nil, "", file.Max)
		if e != nil || actual != file.Expected {
			return nil, empty, ErrRecovery
		}
	}
	trusted, e := lockBytes(ctx, c.ToolLock)
	if e != nil || domain.Hash(trusted) != d.Tools.Digest {
		return nil, empty, ErrRecovery
	}
	p, version, e := databaseContext(ctx, filepath.Join(path, "state.db"))
	if e != nil || version != d.SchemaVersion || domain.Digest(p) != d.Policy {
		return nil, empty, ErrRecovery
	}
	gateway, e := readOwned(ctx, filepath.Join(path, "active.Caddyfile"), 65536, true)
	if e != nil || !bytes.Equal(gateway, gatewayBytes(p)) {
		return nil, empty, ErrRecovery
	}
	valid = true
	return root, m, nil
}
func Verify(ctx context.Context, c Config, path string) (Receipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	root, m, e := verified(ctx, c, path)
	if e != nil {
		return Receipt{}, e
	}
	defer root.close()
	return receipt(m, "bundle_verified"), nil
}
