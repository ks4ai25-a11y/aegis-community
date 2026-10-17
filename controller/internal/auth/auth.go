// SPDX-License-Identifier: BUSL-1.1
package auth

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"net/http"
	"sync"
	"time"
)

func Token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func HashPassword(p string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(hash)
}
func CheckPassword(p, h string) bool {
	var salt, hash []byte
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			salt, _ = base64.RawStdEncoding.DecodeString(h[:i])
			hash, _ = base64.RawStdEncoding.DecodeString(h[i+1:])
			break
		}
	}
	if len(salt) != 16 || len(hash) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(hash, got) == 1
}

type Auth struct {
	S         *store.Store
	Bootstrap string
	Expiry    time.Time
	mu        sync.Mutex
	failures  int
	next      time.Time
}

func New(s *store.Store) *Auth {
	a := &Auth{S: s, Expiry: time.Now().Add(10 * time.Minute)}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM owners").Scan(&n)
	if n == 0 {
		a.Bootstrap = Token()
	}
	return a
}

// Throttle reports whether a sign-in or enrollment attempt may run now. Only
// failed attempts (Fail) start a back-off, so a stream of requests cannot keep
// the owner locked out unless those requests are themselves failing guesses.
func (a *Auth) Throttle() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !time.Now().Before(a.next)
}

// Fail records a failed attempt and doubles the back-off, up to 64 seconds.
func (a *Auth) Fail() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures++
	a.next = time.Now().Add(time.Duration(1<<min(a.failures-1, 6)) * time.Second)
}
func (a *Auth) Reset() { a.mu.Lock(); a.failures = 0; a.next = time.Time{}; a.mu.Unlock() }

// ErrEnrollment is a client-presentable enrollment refusal.
type ErrEnrollment struct{ Reason string }

func (e ErrEnrollment) Error() string { return e.Reason }
func (a *Auth) Enroll(token, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(password) < 14 || len(password) > 256 {
		return ErrEnrollment{"passphrase must have 14–256 characters"}
	}
	if a.Bootstrap == "" || time.Now().After(a.Expiry) || subtle.ConstantTimeCompare([]byte(token), []byte(a.Bootstrap)) != 1 {
		return ErrEnrollment{"invalid or expired enrollment token"}
	}
	tx, e := a.S.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var n int
	if e = tx.QueryRow("SELECT count(*) FROM owners").Scan(&n); e != nil || n != 0 {
		return ErrEnrollment{"enrollment unavailable: an owner already exists"}
	}
	_, e = tx.Exec("INSERT INTO owners VALUES(?,?,?)", domain.ID(), HashPassword(password), domain.Now())
	if e == nil {
		e = tx.Commit()
	}
	if e == nil {
		a.Bootstrap = ""
	}
	return e
}
func (a *Auth) Login(w http.ResponseWriter, r *http.Request, password string) (string, error) {
	var id, hash string
	if e := a.S.DB.QueryRow("SELECT id,password FROM owners LIMIT 1").Scan(&id, &hash); e != nil || !CheckPassword(password, hash) {
		return "", fmt.Errorf("invalid credentials")
	}
	session := Token()
	csrf := csrfForSession(domain.Hash([]byte(session)))
	now := time.Now().Unix()
	_, e := a.S.DB.Exec("INSERT INTO sessions VALUES(?,?,?,?,?,?)", domain.Hash([]byte(session)), id, domain.Hash([]byte(csrf)), now, now, now+8*3600)
	if e != nil {
		return "", e
	}
	http.SetCookie(w, &http.Cookie{Name: "aegis_session", Value: session, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	return csrf, nil
}
func (a *Auth) Session(r *http.Request) (string, string, error) {
	c, e := r.Cookie("aegis_session")
	if e != nil {
		return "", "", e
	}
	var id, csrf string
	var created, seen, expires int64
	hash := domain.Hash([]byte(c.Value))
	e = a.S.DB.QueryRow("SELECT owner,csrf,created,seen,expires FROM sessions WHERE hash=?", hash).Scan(&id, &csrf, &created, &seen, &expires)
	now := time.Now().Unix()
	if e != nil || now > expires || now-seen > 1800 {
		return "", "", fmt.Errorf("session expired")
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if csrf != domain.Hash([]byte(r.Header.Get("X-CSRF-Token"))) {
			return "", "", fmt.Errorf("CSRF required")
		}
	}
	a.S.DB.Exec("UPDATE sessions SET seen=? WHERE hash=?", now, hash)
	return id, hash, nil
}
func (a *Auth) RotateCSRF(hash string) (string, error) {
	// Stable for the session so opening another tab cannot invalidate a form.
	token := csrfForSession(hash)
	_, e := a.S.DB.Exec("UPDATE sessions SET csrf=? WHERE hash=?", domain.Hash([]byte(token)), hash)
	return token, e
}
func Decode(r *http.Request, out any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("application/json required")
	}
	b, e := io.ReadAll(http.MaxBytesReader(nil, r.Body, 65536))
	if e != nil {
		return fmt.Errorf("request exceeds bounded JSON size")
	}
	if e = uniqueKeys(json.NewDecoder(bytes.NewReader(b)), 0); e != nil {
		return e
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e := dec.Decode(out); e != nil {
		return fmt.Errorf("invalid JSON request")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fmt.Errorf("one JSON document required")
	}
	return nil
}

func csrfForSession(hash string) string { return domain.Hash([]byte("aegis-csrf-v1\x00" + hash)) }

// Reject duplicate keys and excessive nesting before typed decoding. Ambiguous
// signed/approved documents must not depend on a parser's first/last-key choice.
func uniqueKeys(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting too deep")
	}
	token, e := d.Token()
	if e != nil {
		return fmt.Errorf("invalid JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return fmt.Errorf("invalid object")
			}
			k, ok := key.(string)
			if !ok || seen[k] {
				return fmt.Errorf("duplicate or invalid object key")
			}
			seen[k] = true
			if e = uniqueKeys(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = uniqueKeys(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, e = d.Token()
	return e
}
