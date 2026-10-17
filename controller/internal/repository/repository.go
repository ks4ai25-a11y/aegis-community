// SPDX-License-Identifier: BUSL-1.1
package repository

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"aegis.local/source"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

var ErrAsset = errors.New("invalid or unavailable provisioned repository asset")
var ErrUnavailable = errors.New("repository mounts not provisioned")
var ErrBudget = errors.New("application map exceeds the current bounded response budget")
var assetID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

type Record struct {
	Schema    string `json:"schema_version"`
	ID        string `json:"repository_id"`
	Owner     string `json:"owner_id"`
	App       string `json:"app_id"`
	Asset     string `json:"asset_id"`
	Mode      string `json:"mode"`
	MapDigest string `json:"map_digest"`
	Created   string `json:"created_at"`
}
type Registry struct {
	S    *store.Store
	Root *os.Root
}

// Connect accepts an asset identifier, never a URL, shell or host filesystem path.
func (r *Registry) Connect(owner, app, asset string, acknowledge bool) (Record, error) {
	return r.ConnectContext(context.Background(), owner, app, asset, acknowledge)
}

func (r *Registry) ConnectContext(ctx context.Context, owner, app, asset string, acknowledge bool) (Record, error) {
	return r.connect(ctx, owner, app, asset, acknowledge, false)
}

// Refresh re-reads an already connected repository (change-triggered rescans).
// It is audited only when the application map actually changed.
func (r *Registry) Refresh(ctx context.Context, owner, id string) (Record, error) {
	rec, e := r.Get(owner, id)
	if e != nil {
		return Record{}, e
	}
	return r.connect(ctx, owner, rec.App, rec.Asset, true, true)
}

// pruneMaps removes the oldest application maps of a repository that are
// neither current nor referenced by any scan job, until fewer than keep remain.
// Scan receipts and leases read their job's map, so referenced maps stay.
func pruneMaps(tx *sql.Tx, repo, current string, keep int) error {
	_, e := tx.Exec(`DELETE FROM application_maps WHERE repository=? AND digest<>? AND digest IN (
		SELECT m.digest FROM application_maps m WHERE m.repository=? AND m.digest<>?
		AND NOT EXISTS (SELECT 1 FROM scanner_jobs j WHERE j.repository=m.repository AND j.map_digest=m.digest)
		ORDER BY m.created_at ASC LIMIT max(0,(SELECT count(*) FROM application_maps WHERE repository=?)-?))`, repo, current, repo, current, repo, keep-1)
	return e
}

func (r *Registry) connect(ctx context.Context, owner, app, asset string, acknowledge, quiet bool) (Record, error) {
	if r.Root == nil {
		return Record{}, ErrUnavailable
	}
	if !acknowledge || app != "app_demo" || !assetID.MatchString(asset) {
		return Record{}, ErrAsset
	}
	if e := r.authorizeMounts(owner, true); e != nil {
		return Record{}, e
	}
	st, e := r.Root.Lstat(asset)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return Record{}, ErrAsset
	}
	anchor, e := r.Root.OpenRoot(asset)
	if e != nil {
		return Record{}, ErrAsset
	}
	defer anchor.Close()
	actual, e := anchor.Stat(".")
	if e != nil || !os.SameFile(st, actual) {
		return Record{}, ErrAsset
	}
	m, e := source.ReadRootContext(ctx, anchor, app, "mounted-asset:"+asset)
	if e != nil {
		return Record{}, ErrAsset
	}
	b, e := json.Marshal(m)
	if e != nil {
		return Record{}, e
	}
	if len(b) > 60000 {
		return Record{}, ErrBudget
	}
	tx, e := r.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return Record{}, e
	}
	defer tx.Rollback()
	var out Record
	changed := false
	e = tx.QueryRow("SELECT id,owner,app,asset,map_digest,created_at FROM repositories WHERE owner=? AND app=? AND asset=?", owner, app, asset).Scan(&out.ID, &out.Owner, &out.App, &out.Asset, &out.MapDigest, &out.Created)
	if e == sql.ErrNoRows {
		changed = true
		var count int
		if e = tx.QueryRow("SELECT count(*) FROM repositories WHERE owner=?", owner).Scan(&count); e != nil {
			return Record{}, e
		}
		if count >= 100 {
			return Record{}, ErrBudget
		}
		out = Record{ID: domain.ID(), Owner: owner, App: app, Asset: asset, MapDigest: m.Digest, Created: domain.Now()}
		_, e = tx.Exec("INSERT INTO repositories VALUES(?,?,?,?,?,?)", out.ID, owner, app, asset, m.Digest, out.Created)
	} else if e == nil && out.MapDigest != m.Digest {
		changed = true
		var count int
		if e = pruneMaps(tx, out.ID, m.Digest, 100); e != nil {
			return Record{}, e
		}
		if e = tx.QueryRow("SELECT count(*) FROM application_maps WHERE repository=? AND digest<>?", out.ID, m.Digest).Scan(&count); e != nil {
			return Record{}, e
		}
		if count >= 100 {
			return Record{}, ErrBudget
		}
		out.MapDigest = m.Digest
		_, e = tx.Exec("UPDATE repositories SET map_digest=? WHERE id=? AND owner=?", m.Digest, out.ID, owner)
	}
	if e != nil {
		return Record{}, e
	}
	var existing int
	if e = tx.QueryRow("SELECT count(*) FROM application_maps WHERE repository=? AND digest=?", out.ID, m.Digest).Scan(&existing); e != nil {
		return Record{}, e
	}
	if existing == 0 {
		var bytes int64
		if e = tx.QueryRow("SELECT coalesce(sum(length(CAST(document AS BLOB))),0) FROM application_maps").Scan(&bytes); e != nil {
			return Record{}, e
		}
		if bytes+int64(len(b)) > 16<<20 {
			// Reclaim this repository's own unreferenced history before refusing.
			if e = pruneMaps(tx, out.ID, m.Digest, 1); e != nil {
				return Record{}, e
			}
			if e = tx.QueryRow("SELECT coalesce(sum(length(CAST(document AS BLOB))),0) FROM application_maps").Scan(&bytes); e != nil {
				return Record{}, e
			}
			if bytes+int64(len(b)) > 16<<20 {
				return Record{}, ErrBudget
			}
		}
	}
	_, e = tx.Exec("INSERT INTO application_maps VALUES(?,?,?,?) ON CONFLICT(repository,digest) DO NOTHING", out.ID, m.Digest, string(b), m.Observed)
	if e != nil {
		return Record{}, e
	}
	if !quiet || changed {
		if e = store.AuditTx(tx, owner, "repository.connect", out.ID, "read_only", map[string]any{"asset_id": asset, "map_digest": m.Digest, "file_count": len(m.Files), "commit_sha": m.Commit, "refresh": quiet}); e != nil {
			return Record{}, e
		}
	}
	if e = tx.Commit(); e != nil {
		return Record{}, e
	}
	out.Schema = "1.0"
	out.Mode = "repo_offline"
	return out, nil
}
func (r *Registry) Get(owner, id string) (Record, error) {
	var out Record
	e := r.S.DB.QueryRow("SELECT id,owner,app,asset,map_digest,created_at FROM repositories WHERE id=? AND owner=?", id, owner).Scan(&out.ID, &out.Owner, &out.App, &out.Asset, &out.MapDigest, &out.Created)
	out.Schema = "1.0"
	out.Mode = "repo_offline"
	return out, e
}
func (r *Registry) Map(owner, id string) (source.Map, error) {
	var raw string
	var out source.Map
	e := r.S.DB.QueryRow("SELECT m.document FROM application_maps m JOIN repositories r ON r.id=m.repository AND r.map_digest=m.digest WHERE r.id=? AND r.owner=?", id, owner).Scan(&raw)
	if e == nil {
		e = json.Unmarshal([]byte(raw), &out)
	}
	return out, e
}
func (r *Registry) List(owner string) ([]Record, error) {
	rows, e := r.S.DB.Query("SELECT id,owner,app,asset,map_digest,created_at FROM repositories WHERE owner=? ORDER BY created_at DESC,id LIMIT 100", owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var v Record
		if e = rows.Scan(&v.ID, &v.Owner, &v.App, &v.Asset, &v.MapDigest, &v.Created); e != nil {
			return nil, e
		}
		v.Schema = "1.0"
		v.Mode = "repo_offline"
		out = append(out, v)
	}
	return out, rows.Err()
}
func (r *Registry) Assets(owner string) ([]string, error) {
	if r.Root == nil {
		return nil, ErrUnavailable
	}
	if e := r.authorizeMounts(owner, false); e != nil {
		return nil, e
	}
	f, e := r.Root.Open(".")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	entries, e := f.ReadDir(101)
	if e != nil && len(entries) == 0 {
		return nil, e
	}
	if len(entries) > 100 {
		return nil, ErrBudget
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() && assetID.MatchString(entry.Name()) {
			out = append(out, entry.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
func Open(s *store.Store, path string) (*Registry, error) {
	r := &Registry{S: s}
	if path == "" {
		return r, nil
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, fmt.Errorf("cannot open provisioned repository root")
	}
	r.Root = root
	return r, nil
}

// Provisioned mounts belong to one durably bound owner, not every account.
func (r *Registry) authorizeMounts(owner string, bind bool) error {
	tx, e := r.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var assigned string
	e = tx.QueryRow("SELECT value FROM settings WHERE key='repository_mount_owner'").Scan(&assigned)
	if e == nil {
		if assigned != owner {
			return ErrAsset
		}
		return nil
	}
	if e != sql.ErrNoRows {
		return e
	}
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM owners").Scan(&count); e != nil {
		return e
	}
	if count != 1 {
		return ErrAsset
	}
	if e = tx.QueryRow("SELECT id FROM owners").Scan(&assigned); e != nil {
		return e
	}
	if assigned != owner {
		return ErrAsset
	}
	if !bind {
		return nil
	}
	if _, e = tx.Exec("INSERT INTO settings VALUES('repository_mount_owner',?)", owner); e != nil {
		return e
	}
	if e = store.AuditTx(tx, owner, "repository.mount_bind", "provisioned-local-tree", "single_owner", nil); e != nil {
		return e
	}
	return tx.Commit()
}

// Excerpt is a bounded view of one inventoried source file around a line.
type Excerpt struct {
	Path      string   `json:"path"`
	Digest    string   `json:"file_digest"`
	StartLine int      `json:"start_line"`
	Lines     []string `json:"lines"`
	// Redacted is true when any line of the file looked like a credential; such
	// lines are replaced in Lines and the file is never sent to a model.
	Redacted bool   `json:"redacted"`
	Content  string `json:"-"`
}

// likelySecret matches common credential shapes. It is a conservative filter for
// display and model input, not a secret scanner.
var likelySecret = regexp.MustCompile(`(?i)(` +
	`gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|` +
	`xox[abposr]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9_-]{20,}|[sr]k_(live|test)_[A-Za-z0-9]{10,}|` +
	`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.|` + // JWT
	`[a-z][a-z0-9+.-]*://[^/\s:@'"]+:[^@\s'"]{3,}@|` + // URL with an embedded password
	`xox[abposre]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|[pr]k_(live|test)_[A-Za-z0-9]{10,}|whsec_[A-Za-z0-9]{16,}|hf_[A-Za-z0-9]{20,}|ya29\.[A-Za-z0-9_-]{20,}|shp(at|ss|ca|pa)_[a-f0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|glsa_[A-Za-z0-9_]{20,}|dop_v1_[a-f0-9]{20,}|AGE-SECRET-KEY-1[A-Z0-9]{20,}|` +
	`[a-z][a-z0-9+.-]*://:[^@\s'"]{3,}@|` + // URL with a password and no user
	`["']?Authorization["']?\s*[:,]\s*["'](Basic|Bearer|Token)\s+[A-Za-z0-9+/=._-]{8,}|` +
	`(curl|wget)\b[^\n]*\s(-u|--user)\s+[^\s:]+:[^\s]{3,}|\b(mysql|mysqldump)\b[^\n]*\s-p[^\s-][^\s]{2,}|` +
	`\bpw["']?\s*[:=]\s*["'][^"']{6,}|AccountKey=[A-Za-z0-9+/=]{20,}|hooks\.slack\.com/services/|discord(app)?\.com/api/webhooks/|` +
	`Authorization:\s*(Basic|Bearer)\s+[A-Za-z0-9+/=._-]{8,}|` +
	`define\(\s*["'][A-Z0-9_]*(PASS|SECRET|KEY|TOKEN)[A-Z0-9_]*["']\s*,\s*["'][^"']{6,}|` + // PHP define()
	`<(password|passwd|secret|api[_-]?key|token|connectionString)>[^<]{6,}<|` + // XML element
	`key\s*=\s*["'][^"']*(key|secret|password|token)[^"']*["']\s+value\s*=\s*["'][^"']{6,}|` + // .NET appSettings
	`(password|passwd|pass|pwd|passphrase|secret|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|hmac[_-]?key|account[_-]?key|token|auth|credential)[a-z0-9_-]*["']?\s*(:=|=>|[:=])\s*["']?[^\s"',;]{6,})`)

// looksSecret treats very long lines (minified bundles, embedded blobs) as
// sensitive without scanning them: they are expensive to match and rarely
// needed to explain a finding.
func looksSecret(line string) bool {
	return len(line) > 4096 || likelySecret.MatchString(line)
}

var ErrSourceChanged = errors.New("source file is not in the current inventory or changed since it was inventoried")

// Excerpt reads a file only if the repository's current application map lists it
// with the same digest, so protected and generated files (never inventoried) and
// modified files are refused. Reads stay inside the asset's os.Root.
func (r *Registry) Excerpt(owner, id, path string, line, radius int) (Excerpt, error) {
	rec, e := r.Get(owner, id)
	if e != nil {
		return Excerpt{}, e
	}
	m, e := r.Map(owner, id)
	if e != nil {
		return Excerpt{}, e
	}
	digest := ""
	for _, f := range m.Files {
		if f.Path == path {
			digest = f.Digest
		}
	}
	if digest == "" || r.Root == nil || line < 1 || radius < 0 || radius > 40 {
		return Excerpt{}, ErrSourceChanged
	}
	anchor, e := r.Root.OpenRoot(rec.Asset)
	if e != nil {
		return Excerpt{}, e
	}
	defer anchor.Close()
	f, e := anchor.Open(path)
	if e != nil {
		return Excerpt{}, ErrSourceChanged
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 || domain.Hash(b) != digest {
		return Excerpt{}, ErrSourceChanged
	}
	all := strings.Split(string(b), "\n")
	redacted := false
	for _, l := range all {
		if looksSecret(l) {
			redacted = true
		}
	}
	start := max(1, line-radius)
	end := min(len(all), line+radius)
	out := Excerpt{Path: path, Digest: digest, StartLine: start, Content: string(b), Redacted: redacted}
	for i := start; i <= end; i++ {
		v := all[i-1]
		if looksSecret(v) {
			v = "[redacted: possible credential]"
		}
		if len(v) > 400 {
			v = v[:400]
		}
		out.Lines = append(out.Lines, v)
	}
	return out, nil
}
