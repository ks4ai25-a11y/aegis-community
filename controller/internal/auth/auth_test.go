package auth

import (
	"aegis.local/controller/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAU001BootstrapOneTime(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := New(s)
	token := a.Bootstrap
	if e = a.Enroll(token, "a sufficiently long passphrase"); e != nil {
		t.Fatal(e)
	}
	if e = a.Enroll(token, "a sufficiently long passphrase"); e == nil {
		t.Fatal("bootstrap replay accepted")
	}
}
func TestStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"command":"rm -rf"}`, `{} {}`, `{invalid}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		var target struct {
			Password string `json:"password"`
		}
		if Decode(r, &target) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestAU002SessionCSRFAndLogout(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := New(s)
	if e = a.Enroll(a.Bootstrap, "a sufficiently long passphrase"); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	csrf, e := a.Login(w, r, "a sufficiently long passphrase")
	if e != nil {
		t.Fatal(e)
	}
	r.AddCookie(w.Result().Cookies()[0])
	if _, _, e = a.Session(r); e == nil {
		t.Fatal("mutation without csrf accepted")
	}
	r.Header.Set("X-CSRF-Token", csrf)
	_, hash, e := a.Session(r)
	if e != nil {
		t.Fatal(e)
	}
	first, e := a.RotateCSRF(hash)
	if e != nil {
		t.Fatal(e)
	}
	second, e := a.RotateCSRF(hash)
	if e != nil || first != second || first != csrf {
		t.Fatal("tabs invalidate CSRF", e)
	}
	s.DB.Exec("DELETE FROM sessions WHERE hash=?", hash)
	if _, _, e = a.Session(r); e == nil {
		t.Fatal("revoked session accepted")
	}
}

func TestDuplicateJSONKeysRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"password":"first","password":"second"}`))
	r.Header.Set("Content-Type", "application/json")
	var in struct {
		Password string `json:"password"`
	}
	if Decode(r, &in) == nil {
		t.Fatal("ambiguous request accepted")
	}
}
