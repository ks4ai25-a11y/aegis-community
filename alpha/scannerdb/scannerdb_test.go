// SPDX-License-Identifier: BUSL-1.1
package scannerdb

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func archive(t *testing.T) []byte {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("GHSA-test.json")
	w.Write([]byte(`{"id":"GHSA-test"}`))
	z.Close()
	return b.Bytes()
}

func TestFetchVerifyTamperAndMount(t *testing.T) {
	body := archive(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/all.zip") {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Last-Modified", "Thu, 15 Oct 2026 10:00:00 GMT")
		w.Write(body)
	}))
	defer srv.Close()
	root := t.TempDir()
	client := &http.Client{Transport: rewrite{srv.URL}}
	db, e := FetchOSV(context.Background(), root, []string{"npm", "PyPI"}, client)
	if e != nil || len(db.Files) != 2 || db.Files[0].Path != "osv-scalibr/PyPI/all.zip" || db.BuiltAt != "2026-10-15T10:00:00Z" {
		t.Fatal(db, e)
	}
	if _, e = WriteManifest(root, db); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	st, e := Verify(root, 7*24*time.Hour, now)
	if e != nil || len(st) != 1 || st[0].Stale || st[0].AgeHours != 48 {
		t.Fatal(st, e)
	}
	if st, _ = Verify(root, 24*time.Hour, now); !st[0].Stale {
		t.Fatal("old database not flagged stale")
	}
	m, e := MountFor(root, "osv_v2")
	if e != nil || !m.ReadOnly || m.ContainerPath != "/db/osv" || m.Env[0] != "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv" {
		t.Fatal(m, e)
	}
	if m, _ = MountFor(root, "trivy"); strings.Join(m.ExtraArgs, " ") != "--cache-dir /db/trivy" {
		t.Fatal(m)
	}
	if _, e = MountFor(root, "semgrep_ce"); e == nil {
		t.Fatal("database for tool without one")
	}
	// Any modification is detected.
	os.WriteFile(filepath.Join(root, "osv", "osv-scalibr", "npm", "all.zip"), []byte("tampered"), 0640)
	if _, e = Verify(root, time.Hour, now); e == nil {
		t.Fatal("tampered database verified")
	}
	os.WriteFile(filepath.Join(root, ManifestName), []byte(`{"schema_version":"1.0","databases":[],"manifest_digest":"sha256:x"}`), 0640)
	if _, e = Verify(root, time.Hour, now); e == nil {
		t.Fatal("forged manifest accepted")
	}
}

func TestFetchRejectsBadInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not a zip")) }))
	defer srv.Close()
	client := &http.Client{Transport: rewrite{srv.URL}}
	root := t.TempDir()
	if _, e := FetchOSV(context.Background(), root, []string{"npm"}, client); e == nil {
		t.Fatal("invalid archive accepted")
	}
	if _, e := FetchOSV(context.Background(), root, []string{"../x"}, client); e == nil {
		t.Fatal("path-like ecosystem accepted")
	}
	if _, e := os.Stat(filepath.Join(root, "osv")); e == nil {
		t.Fatal("failed fetch installed files")
	}
	if _, e := FetchTrivy(context.Background(), root, "aquasec/trivy:latest"); e == nil {
		t.Fatal("unpinned trivy image accepted")
	}
}

type rewrite struct{ base string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := r.base + req.URL.Path
	nr, _ := http.NewRequestWithContext(req.Context(), req.Method, u, nil)
	return http.DefaultTransport.RoundTrip(nr)
}
