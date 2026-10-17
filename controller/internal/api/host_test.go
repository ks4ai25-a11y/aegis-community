package api

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostAllowlist(t *testing.T) {
	for h, want := range map[string]bool{"127.0.0.1:7410": true, "localhost:18443": true, "[::1]:7410": true, "127.9.0.1": true, "attacker.example:7410": false, "127.0.0.1.attacker.example": false, "": false} {
		if allowedHost(h) != want {
			t.Error(h, want)
		}
	}
	t.Setenv("AEGIS_CONSOLE_HOSTS", "aegis.internal.example, console.example:8443")
	if !allowedHost("aegis.internal.example:7410") || !allowedHost("console.example:8443") || allowedHost("console.example:9999") {
		t.Fatal("configured hosts")
	}
}

// QA finding: a DNS-rebinding page could keep the global login throttle armed,
// locking the owner out. Foreign Host names are refused before routing, and
// only failed attempts start a back-off.
func TestRebindingCannotLockOutOwner(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "host.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	if e = a.Enroll(a.Bootstrap, "a sufficiently long test passphrase"); e != nil {
		t.Fatal(e)
	}
	h := (&Server{S: s, A: a, Assets: t.TempDir()}).Handler()
	post := func(host, body string) int {
		r := httptest.NewRequest("POST", "http://"+host+"/api/v1/auth/login", strings.NewReader(body))
		r.Host = host
		r.Header.Set("Origin", "http://"+host)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 5; i++ {
		if c := post("attacker.example:7410", `{"password":"wrong"}`); c != 421 {
			t.Fatal("rebinding host reached login:", c)
		}
	}
	if c := post("127.0.0.1:7410", `{"password":"a sufficiently long test passphrase"}`); c != 200 {
		t.Fatal("owner locked out:", c)
	}
	if c := post("127.0.0.1:7410", `{"password":"wrong"}`); c != 403 {
		t.Fatal(c)
	}
	if c := post("127.0.0.1:7410", `{"password":"a sufficiently long test passphrase"}`); c != 429 {
		t.Fatal("failed guess did not start a back-off:", c)
	}
}

// QA round 2: concurrent guesses must not all pass the back-off at once.
func TestConcurrentLoginGuessesAreSerialised(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "burst.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	a.Enroll(a.Bootstrap, "a sufficiently long test passphrase")
	h := (&Server{S: s, A: a, Assets: t.TempDir()}).Handler()
	codes := make(chan int, 16)
	for i := 0; i < 16; i++ {
		go func() {
			r := httptest.NewRequest("POST", "http://127.0.0.1:7410/api/v1/auth/login", strings.NewReader(`{"password":"wrong"}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	checked := 0
	for i := 0; i < 16; i++ {
		if <-codes == 403 {
			checked++
		}
	}
	if checked > 2 {
		t.Fatal("password checks ran concurrently:", checked)
	}
}
