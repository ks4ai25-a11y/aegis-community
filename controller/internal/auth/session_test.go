// SPDX-License-Identifier: BUSL-1.1
package auth

import (
	"aegis.local/controller/internal/store"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// QA: sessions were never pruned and old cookies survived later sign-ins.
func TestLoginPrunesAndCapsSessions(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "sessions.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	a := New(s)
	if e = a.Enroll(a.Bootstrap, "a sufficiently long test passphrase"); e != nil {
		t.Fatal(e)
	}
	s.DB.Exec("INSERT INTO sessions VALUES('stale',(SELECT id FROM owners),'c',1,1,?)", time.Now().Unix()+3600)
	for i := 0; i < 8; i++ {
		if _, e = a.Login(httptest.NewRecorder(), httptest.NewRequest("POST", "http://127.0.0.1", nil), "a sufficiently long test passphrase"); e != nil {
			t.Fatal(e)
		}
	}
	var n, stale int
	s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&n)
	s.DB.QueryRow("SELECT count(*) FROM sessions WHERE hash='stale'").Scan(&stale)
	if n != 5 || stale != 0 {
		t.Fatal("sessions not pruned/capped", n, stale)
	}
}

func TestSecureCookieBehindConfiguredTLSOrigin(t *testing.T) {
	r := httptest.NewRequest("POST", "http://127.0.0.1:7410", nil)
	if SecureRequest(r) {
		t.Fatal("plain loopback marked secure")
	}
	t.Setenv("AEGIS_PUBLIC_ORIGIN", "https://aegis.example.internal/")
	if !SecureRequest(r) || PublicOrigin() != "https://aegis.example.internal" {
		t.Fatal("configured TLS origin not honoured")
	}
}
