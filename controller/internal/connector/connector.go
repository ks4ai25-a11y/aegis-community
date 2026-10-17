// SPDX-License-Identifier: BUSL-1.1
// Package connector issues owner-scoped, read-only bearer credentials for local
// assistants (for example an MCP bridge started by a desktop AI app). A credential
// can only read defence data through an explicit route allowlist; it can never
// change policy, start jobs or read scanner/worker channels.
package connector

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	Scope  = "read_defence_v1"
	prefix = "aegis_ct_"
)

var (
	ErrInvalid  = errors.New("connector credential invalid, expired or revoked")
	ErrConflict = errors.New("connector credential not found or already revoked")
	tokenShape  = regexp.MustCompile(`^aegis_ct_[0-9a-f]{64}$`)
	nameShape   = regexp.MustCompile(`^[A-Za-z0-9 ._()-]{1,64}$`)
	id          = `[A-Za-z0-9_.:-]{1,160}`
	// Read-only routes a connector may call. Anything else is refused before routing.
	allowed = []*regexp.Regexp{
		regexp.MustCompile(`^/system/status$`),
		regexp.MustCompile(`^/sites$`),
		regexp.MustCompile(`^/sites/` + id + `/(incidents|endpoints|policy|events)$`),
		regexp.MustCompile(`^/incidents/` + id + `$`),
		regexp.MustCompile(`^/incidents/` + id + `/(assessment|proposals)$`),
		regexp.MustCompile(`^/ai/status$`),
		regexp.MustCompile(`^/adapters$`),
		regexp.MustCompile(`^/findings/catalogue$`),
	}
)

type Credential struct {
	ID       string `json:"connector_id"`
	Name     string `json:"name"`
	Scope    string `json:"scope"`
	State    string `json:"state"`
	Created  string `json:"created_at"`
	Expires  int64  `json:"expires_unix"`
	LastUsed int64  `json:"last_used_unix"`
}

type Registry struct {
	S   *store.Store
	Now func() time.Time
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Allowed reports whether a connector may call method+path (API-relative path).
func Allowed(method, path string) bool {
	if method != "GET" {
		return false
	}
	for _, re := range allowed {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// Issue creates a credential and returns its token exactly once.
func (r *Registry) Issue(owner, name string, ttl time.Duration) (Credential, string, error) {
	if !nameShape.MatchString(name) || ttl < time.Hour || ttl > 30*24*time.Hour {
		return Credential{}, "", errors.New("name must be 1–64 plain characters and lifetime 1–720 hours")
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return Credential{}, "", e
	}
	token := prefix + hex.EncodeToString(b)
	c := Credential{ID: domain.ID(), Name: name, Scope: Scope, State: "active", Created: domain.Now(), Expires: r.now().Add(ttl).Unix()}
	tx, e := r.S.DB.Begin()
	if e != nil {
		return Credential{}, "", e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO connector_credentials(id,owner,name,token_hash,scope,state,created_at,expires) VALUES(?,?,?,?,?,?,?,?)", c.ID, owner, c.Name, domain.Hash([]byte(token)), Scope, "active", c.Created, c.Expires); e != nil {
		return Credential{}, "", e
	}
	if e = store.AuditTx(tx, owner, "connector.issued", c.ID, "active", map[string]any{"name": c.Name, "scope": Scope, "expires_unix": c.Expires}); e != nil {
		return Credential{}, "", e
	}
	return c, token, tx.Commit()
}

func (r *Registry) List(owner string) ([]Credential, error) {
	rows, e := r.S.DB.Query("SELECT id,name,scope,state,created_at,expires,last_used FROM connector_credentials WHERE owner=? ORDER BY created_at DESC LIMIT 100", owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Credential{}
	now := r.now().Unix()
	for rows.Next() {
		var c Credential
		if e = rows.Scan(&c.ID, &c.Name, &c.Scope, &c.State, &c.Created, &c.Expires, &c.LastUsed); e != nil {
			return nil, e
		}
		if c.State == "active" && c.Expires <= now {
			c.State = "expired"
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Registry) Revoke(owner, connector string) error {
	tx, e := r.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE connector_credentials SET state='revoked' WHERE id=? AND owner=? AND state='active'", connector, owner)
	if e != nil {
		return e
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	if e = store.AuditTx(tx, owner, "connector.revoked", connector, "revoked", nil); e != nil {
		return e
	}
	return tx.Commit()
}

// Authenticate resolves an Authorization header to the issuing owner.
func (r *Registry) Authenticate(header string) (owner, connector string, err error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || !tokenShape.MatchString(token) {
		return "", "", ErrInvalid
	}
	now := r.now().Unix()
	e := r.S.DB.QueryRow("SELECT owner,id FROM connector_credentials WHERE token_hash=? AND state='active' AND expires>?", domain.Hash([]byte(token)), now).Scan(&owner, &connector)
	if e == sql.ErrNoRows || e != nil {
		return "", "", ErrInvalid
	}
	r.S.DB.Exec("UPDATE connector_credentials SET last_used=? WHERE id=? AND last_used<?", now, connector, now-30)
	return owner, connector, nil
}
