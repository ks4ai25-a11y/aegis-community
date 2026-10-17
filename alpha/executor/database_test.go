// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"aegis.local/alpha/scannerdb"
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type redirect struct{ base string }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	nr, _ := http.NewRequestWithContext(req.Context(), req.Method, r.base+req.URL.Path, nil)
	return http.DefaultTransport.RoundTrip(nr)
}

func osvRoot(t *testing.T) string {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("GHSA-test.json")
	w.Write([]byte(`{"id":"GHSA-test"}`))
	z.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Thu, 15 Oct 2026 10:00:00 GMT")
		w.Write(b.Bytes())
	}))
	t.Cleanup(srv.Close)
	root := t.TempDir()
	db, e := scannerdb.FetchOSV(context.Background(), root, []string{"npm"}, &http.Client{Transport: redirect{srv.URL}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = scannerdb.WriteManifest(root, db); e != nil {
		t.Fatal(e)
	}
	return root
}

func TestDatabaseIsVerifiedBeforeMounting(t *testing.T) {
	t.Setenv("AEGIS_SCANNER_DB_ROOT", "")
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	if use, mount, e := (Config{}).database("osv_v2", now); use != nil || mount != nil || e != nil {
		t.Fatal("database used without operator configuration")
	}
	root := osvRoot(t)
	use, mount, e := (Config{DatabaseRoot: root}).database("osv_v2", now)
	if e != nil || use.ContainerPath != "/db/osv" || use.Stale || use.AgeHours != 48 || mount.Target != "/db/osv" || mount.Source != filepath.Join(root, "osv") || mount.Env[0] != "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv" {
		t.Fatal(use, mount, e)
	}
	if use, _, _ = (Config{DatabaseRoot: root, DatabaseMaxAge: time.Hour}).database("osv_v2", now); !use.Stale {
		t.Fatal("old database not reported stale")
	}
	if use, mount, e = (Config{DatabaseRoot: root}).database("bandit", now); use != nil || mount != nil || e != nil {
		t.Fatal("non-advisory tool given a database")
	}
	if _, _, e = (Config{DatabaseRoot: root}).database("trivy", now); e == nil {
		t.Fatal("missing tool database not refused")
	}
	for _, bad := range []string{"relative/db", root + "/../x", root + ",dst=/etc"} {
		if _, _, e = (Config{DatabaseRoot: bad}).database("osv_v2", now); e == nil {
			t.Fatal("unsafe root accepted", bad)
		}
	}
	zipPath := filepath.Join(root, "osv", "osv-scalibr", "npm", "all.zip")
	f, _ := os.OpenFile(zipPath, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("x"))
	f.Close()
	if _, _, e = (Config{DatabaseRoot: root}).database("osv_v2", now); e == nil {
		t.Fatal("tampered database mounted")
	}
}
