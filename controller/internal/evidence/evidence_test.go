// SPDX-License-Identifier: BUSL-1.1
package evidence

import (
	"aegis.local/controller/internal/domain"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func report() (json.RawMessage, string) {
	r := domain.Report{Schema: "1.0", ID: "r1", Overall: "PASS"}
	r.Digest = domain.Digest(r)
	b, _ := json.Marshal(r)
	return b, r.Digest
}

func TestSignVerifyAndTamper(t *testing.T) {
	dir := t.TempDir()
	s, e := LoadOrCreate(dir)
	if e != nil {
		t.Fatal(e)
	}
	again, e := LoadOrCreate(dir)
	if e != nil || KeyID(again.Public()) != KeyID(s.Public()) {
		t.Fatal("key not persisted", e)
	}
	if st, _ := os.Stat(filepath.Join(dir, "evidence-signing.key")); st.Mode().Perm() != 0600 {
		t.Fatal("key file not private")
	}
	doc, d := report()
	env := s.Sign(doc, d)
	if e = Verify(env, ReportDigest, ""); e != nil {
		t.Fatal(e)
	}
	if e = Verify(env, ReportDigest, env.KeyID); e != nil {
		t.Fatal("pinned key refused", e)
	}
	other, _ := LoadOrCreate(t.TempDir())
	if Verify(env, ReportDigest, KeyID(other.Public())) == nil {
		t.Fatal("untrusted key accepted")
	}
	tampered := env
	tampered.Document = json.RawMessage(string(doc[:len(doc)-1]) + `,"overall":"FAIL"}`)
	if Verify(tampered, ReportDigest, "") == nil {
		t.Fatal("tampered document accepted")
	}
	forged := other.Sign(doc, d)
	forged.KeyID = env.KeyID
	if Verify(forged, ReportDigest, "") == nil {
		t.Fatal("key id mismatch accepted")
	}
	os.Chmod(filepath.Join(dir, "evidence-signing.key"), 0644)
	if _, e = LoadOrCreate(dir); e == nil {
		t.Fatal("world-readable key accepted")
	}
}
