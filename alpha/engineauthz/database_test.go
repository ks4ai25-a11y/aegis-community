// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineprofile"
	"aegis.local/alpha/scannerdb"
	"aegis.local/source"
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type rewrite struct{ base string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	nr, _ := http.NewRequestWithContext(req.Context(), req.Method, r.base+req.URL.Path, nil)
	return http.DefaultTransport.RoundTrip(nr)
}

// The admitted path accepts the advisory database only as the fixed,
// read-only mount from the configured, verified root (ADR 068).
func TestDatabaseMountAdmission(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	work := filepath.Join(root, "work")
	for _, d := range []string{"work", "work/source", "work/guard"} {
		os.Mkdir(filepath.Join(root, d), 0700)
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("GHSA-test.json")
	w.Write([]byte(`{"id":"GHSA-test"}`))
	z.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(b.Bytes()) }))
	defer srv.Close()
	dbRoot := filepath.Join(root, "db")
	os.Mkdir(dbRoot, 0755)
	db, e := scannerdb.FetchOSV(context.Background(), dbRoot, []string{"npm"}, &http.Client{Transport: rewrite{srv.URL}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = scannerdb.WriteManifest(dbRoot, db); e != nil {
		t.Fatal(e)
	}
	request := func(cfg Config, d *engineprofile.Database) Decision {
		p, e := Open(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		profile := engineprofile.CreateTrackedWithDatabase("osv_v2", testImage, testName, filepath.Join(work, "source"), "", filepath.Join(work, "guard"), 120, time.Now().UTC().Add(120*time.Second), cfg.UID, cfg.GID, 123, d)
		body, _ := json.Marshal(profile)
		return p.AuthorizeRequest(Request{User: Broker, UserAuthNMethod: "TLS", RequestPeerCertificates: nativeTestPeer(Broker), RequestMethod: "POST", RequestURI: api + "/containers/create?name=" + testName, RequestBody: body, RequestHeaders: map[string]string{"Content-Type": "application/json"}})
	}
	n := 0
	config := func(dbRoot string) Config {
		n++
		cfg := Config{WorkRoot: work, JournalRoot: filepath.Join(root, "journal", string(rune('a'+n))), EngineDigest: source.Hash([]byte("authz-test-engine")), UID: 10001, GID: 10001, Images: map[string]string{"osv_v2": testImage}, DatabaseRoot: dbRoot}
		os.MkdirAll(filepath.Dir(cfg.JournalRoot), 0700)
		if _, e := enginejournal.InitializeEmpty(cfg.JournalRoot, cfg.EngineDigest); e != nil {
			t.Fatal(e)
		}
		return cfg
	}
	good := &engineprofile.Database{Source: filepath.Join(dbRoot, "osv"), Target: "/db/osv", Env: []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv"}}
	must(t, request(config(dbRoot), good), true)
	must(t, request(config(""), good), false) // not configured
	other := *good
	other.Source = filepath.Join(work, "source")
	must(t, request(config(dbRoot), &other), false) // arbitrary path
	wrongTarget := *good
	wrongTarget.Target = "/db/trivy"
	must(t, request(config(dbRoot), &wrongTarget), false) // another tool's path
	noEnv := *good
	noEnv.Env = nil
	must(t, request(config(dbRoot), &noEnv), false) // profile must match exactly
	// Tampering is caught by the authorizer's own re-verification.
	zipPath := filepath.Join(dbRoot, "osv", "osv-scalibr", "npm", "all.zip")
	f, _ := os.OpenFile(zipPath, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("x"))
	f.Close()
	must(t, request(config(dbRoot), good), false)
}
