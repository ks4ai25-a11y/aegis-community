// SPDX-License-Identifier: BUSL-1.1
package engineauthz_test

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/engineprofile"
	"aegis.local/alpha/enginetls"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A native CI-only trusted client asks the actual TLS engine for the precise
// profile under an unregistered name. No test binary is shipped in an image.
func TestRealPackagedGateRefusesUnregisteredLaunch(t *testing.T) {
	if os.Getenv("AEGIS_PACKAGED_CONTROLLER_GATE_TEST") != "1" {
		t.Skip("explicit disposable controller gate fixture only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 10001 || os.Getegid() != 10001 {
		t.Fatal("dedicated unprivileged Linux fixture required")
	}
	u, e := url.Parse(os.Getenv("AEGIS_GATE_PROBE_ENDPOINT"))
	if e != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		t.Fatal("fixed private engine endpoint required")
	}
	registry := os.Getenv("AEGIS_GATE_PROBE_REGISTRY")
	canonical, e := filepath.EvalSymlinks(registry)
	if e != nil || registry != canonical || !filepath.IsAbs(registry) || filepath.Base(registry) != "aegis-scanner-workspaces-10001" || !strings.HasPrefix(filepath.Base(filepath.Dir(registry)), "aegis-worker-runtime-") {
		t.Fatal("owned registry required")
	}
	journal := os.Getenv("AEGIS_GATE_PROBE_JOURNAL")
	if !filepath.IsAbs(journal) || filepath.Base(journal) != "bound-journal" || !strings.HasPrefix(filepath.Base(filepath.Dir(filepath.Dir(journal))), "aegis-packaged-engine-") {
		t.Fatal("separate private plugin journal required")
	}
	identity, e := enginetls.Load(os.Getenv("AEGIS_GATE_PROBE_TLS"), enginetls.Broker)
	if e != nil {
		t.Fatal("private test client identity unavailable")
	}
	images, _, e := engineauthz.ReadLock(os.Getenv("AEGIS_GATE_PROBE_LOCK"))
	if e != nil {
		t.Fatal("pinned tools unavailable")
	}
	dir, e := os.MkdirTemp(registry, "unregistered-probe-")
	if e != nil {
		t.Fatal("probe input unavailable")
	}
	denied := false
	defer func() {
		if denied {
			if e := os.RemoveAll(dir); e != nil {
				t.Error("denied probe input cleanup failed")
			}
		}
	}()
	for _, child := range []string{"source", "guard"} {
		if e = os.Mkdir(filepath.Join(dir, child), 0700); e != nil {
			t.Fatal("probe directory unavailable")
		}
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-" + hex.EncodeToString(nonce)
	profile := engineprofile.CreateTracked("bandit", images["bandit"], name, filepath.Join(dir, "source"), "", filepath.Join(dir, "guard"), 30, time.Now().UTC().Add(time.Minute), 10001, 10001, os.Getpid())
	raw, e := json.Marshal(profile)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "POST", u.String()+"/v1.55/containers/create?name="+name, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, TLSClientConfig: identity.TLS, ResponseHeaderTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		t.Fatal("unregistered launch refusal unavailable")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(body) > 65536 || response.StatusCode != 403 {
		t.Fatal("unregistered engine launch was not refused")
	}
	if _, e = os.Lstat(filepath.Join(journal, name)); !os.IsNotExist(e) {
		t.Fatal("unregistered launch reached plugin mutation journal")
	}
	denied = true
}
