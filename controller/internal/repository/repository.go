// SPDX-License-Identifier: Apache-2.0
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
	"os"
	"regexp"
	"sort"
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
	e = tx.QueryRow("SELECT id,owner,app,asset,map_digest,created_at FROM repositories WHERE owner=? AND app=? AND asset=?", owner, app, asset).Scan(&out.ID, &out.Owner, &out.App, &out.Asset, &out.MapDigest, &out.Created)
	if e == sql.ErrNoRows {
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
		var count int
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
			return Record{}, ErrBudget
		}
	}
	_, e = tx.Exec("INSERT INTO application_maps VALUES(?,?,?,?) ON CONFLICT(repository,digest) DO NOTHING", out.ID, m.Digest, string(b), m.Observed)
	if e != nil {
		return Record{}, e
	}
	if e = store.AuditTx(tx, owner, "repository.connect", out.ID, "read_only", map[string]any{"asset_id": asset, "map_digest": m.Digest, "file_count": len(m.Files), "commit_sha": m.Commit}); e != nil {
		return Record{}, e
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
