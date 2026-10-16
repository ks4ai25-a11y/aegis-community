// SPDX-License-Identifier: Apache-2.0
package engineauthz_test

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/engineprofile"
	"aegis.local/alpha/scanners"
	"aegis.local/source"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
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

// This test never starts/reconfigures a daemon. Only the guarded CI fixture
// provisions one in fresh nonce-owned directories on its disposable runner.
func TestRealDaemonAuthorizationAndStaticScanner(t *testing.T) {
	if os.Getenv("AEGIS_REAL_ENGINE_AUTHZ_TEST") != "1" {
		t.Skip("isolated Linux CI daemon only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() <= 0 {
		t.Fatal("disposable unprivileged Linux CI client required")
	}
	endpoint := os.Getenv("AEGIS_AUTHZ_TEST_ENDPOINT")
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Path != "" || u.RawQuery != "" {
		t.Fatal("fixed loopback TLS endpoint required")
	}
	root := os.Getenv("AEGIS_AUTHZ_TEST_ROOT")
	canonical, e := filepath.EvalSymlinks(root)
	if e != nil || root != canonical || !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "aegis-authz-ci-") {
		t.Fatal("owned fixture root required")
	}
	ca, e := os.ReadFile(filepath.Join(root, "tls", "ca.pem"))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("CA")
	}
	clients := map[string]*http.Client{}
	for _, role := range []string{"broker", "observer", "unknown"} {
		cert, e := tls.LoadX509KeyPair(filepath.Join(root, "tls", role+".pem"), filepath.Join(root, "tls", role+".key"))
		if e != nil {
			t.Fatal(e)
		}
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}, MaxConnsPerHost: 4, ResponseHeaderTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
		defer tr.CloseIdleConnections()
		clients[role] = &http.Client{Transport: tr, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	request := func(role, method, path string, body []byte) (int, []byte) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, method, endpoint+"/v1.55"+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		res, e := clients[role].Do(r)
		if e != nil {
			t.Fatal("isolated engine request failed", e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 65537))
		if e != nil || len(b) > 65536 {
			t.Fatal("bounded response")
		}
		return res.StatusCode, b
	}
	checks := []string{}
	for _, role := range []string{"broker", "observer"} {
		status, _ := request(role, "GET", "/info", nil)
		if status != 200 {
			t.Fatal("allowed read failed", role, status)
		}
	}
	status, _ := request("unknown", "GET", "/info", nil)
	if status != 403 {
		t.Fatal("unknown principal accepted", status)
	}
	checks = append(checks, "TLS principals and observer read")
	for _, path := range []string{"/containers/json", "/images/json", "/networks", "/volumes", "/plugins", "/info?unexpected=1"} {
		status, _ := request("broker", "GET", path, nil)
		if status != 403 {
			t.Fatal("broad API access", path, status)
		}
	}
	for _, path := range []string{"/containers/prune", "/images/create?fromImage=alpine", "/build", "/grpc"} {
		status, _ := request("broker", "POST", path, []byte(`{}`))
		if status != 403 {
			t.Fatal("unapproved write API", path, status)
		}
	}
	checks = append(checks, "broad reads and non-scanner writes denied")
	work := filepath.Join(root, "work")
	repo := filepath.Join(work, "repository")
	if e = os.Mkdir(repo, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(repo, "query.py"), []byte("def unsafe(code):\n    return eval(code)\n"), 0600); e != nil {
		t.Fatal(e)
	}
	rr, e := os.OpenRoot(repo)
	if e != nil {
		t.Fatal(e)
	}
	defer rr.Close()
	m, e := source.ReadRootContext(ctx, rr, "authz-ci", "isolated-static-fixture")
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := source.Capture(ctx, rr, m, work)
	if e != nil {
		t.Fatal(e)
	}
	guard := filepath.Join(work, "guard")
	if e = os.Mkdir(guard, 0700); e != nil {
		t.Fatal(e)
	}
	guardBytes, e := os.ReadFile("../../bin/scanner-guard-linux-amd64")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(guard, "scanner-guard"), guardBytes, 0500); e != nil {
		t.Fatal(e)
	}
	manifest, _ := json.Marshal(snapshot.Manifest)
	if e = os.WriteFile(filepath.Join(guard, "input-manifest.json"), manifest, 0400); e != nil {
		t.Fatal(e)
	}
	images, _, e := engineauthz.ReadLock("../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	name := "aegis-scan-" + hex.EncodeToString(nonce)
	profile := engineprofile.CreateTracked("bandit", images["bandit"], name, snapshot.Path, "", guard, 120, time.Now().Add(120*time.Second), os.Geteuid(), os.Getegid(), os.Getpid())
	b, _ := json.Marshal(profile)
	status, _ = request("observer", "POST", "/containers/create?name="+name, b)
	if status != 403 {
		t.Fatal("observer mutation accepted", status)
	}
	profile.HostConfig.Privileged = true
	bad, _ := json.Marshal(profile)
	status, _ = request("broker", "POST", "/containers/create?name="+name, bad)
	if status != 403 {
		t.Fatal("privileged create accepted", status)
	}
	profile.HostConfig.Privileged = false
	profile.HostConfig.Mounts[0].ReadOnly = false
	bad, _ = json.Marshal(profile)
	status, _ = request("broker", "POST", "/containers/create?name="+name, bad)
	if status != 403 {
		t.Fatal("writable source accepted", status)
	}
	profile.HostConfig.Mounts[0].ReadOnly = true
	checks = append(checks, "observer writes and unsafe scanner profiles denied")
	status, response := request("broker", "POST", "/containers/create?name="+name, b)
	if status != 201 {
		t.Fatalf("fixed scanner create denied: %d %s", status, response)
	}
	var created container.CreateResponse
	if json.Unmarshal(response, &created) != nil || len(created.ID) != 64 {
		t.Fatal("create identity")
	}
	id := created.ID
	// No generic cleanup fallback: only this exact journal-tracked container may
	// be removed, and failed cleanup retains the private daemon fixture for audit.
	wrong := strings.Repeat("a", 64)
	status, _ = request("broker", "POST", "/containers/"+wrong+"/start", nil)
	if status != 403 {
		t.Fatal("unrelated container start accepted", status)
	}
	status, _ = request("observer", "DELETE", "/containers/"+id+"?force=1&v=1", nil)
	if status != 403 {
		t.Fatal("observer remove accepted", status)
	}
	sdk, e := client.New(client.WithHost("tcp://"+u.Host), client.WithScheme("https"), client.WithAPIVersion("1.55"), client.WithHTTPClient(clients["broker"]))
	if e != nil {
		t.Fatal(e)
	}
	defer sdk.Close()
	wait := sdk.ContainerWait(ctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	attachReq, _ := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1.55/containers/"+id+"/attach?stderr=1&stdout=1&stream=1", nil)
	attachReq.Header.Set("Connection", "Upgrade")
	attachReq.Header.Set("Upgrade", "tcp")
	attach, e := clients["broker"].Do(attachReq)
	if e != nil {
		t.Fatal(e)
	}
	defer attach.Body.Close()
	if attach.StatusCode != 101 {
		t.Fatal("attach denied", attach.StatusCode)
	}
	output := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(io.LimitReader(attach.Body, 8<<20)); output <- b }()
	status, _ = request("broker", "POST", "/containers/"+id+"/start", nil)
	if status != 204 {
		t.Fatal("start denied", status)
	}
	select {
	case result := <-wait.Result:
		if result.StatusCode != 1 {
			t.Fatal("expected Bandit fixture finding", result.StatusCode)
		}
	case e := <-wait.Error:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal("scan deadline")
	}
	frames := <-output
	stdout := []byte{}
	for len(frames) > 0 {
		if len(frames) < 8 {
			t.Fatal("stream frame")
		}
		n := int(binary.BigEndian.Uint32(frames[4:8]))
		if n > len(frames)-8 || n < 0 {
			t.Fatal("stream budget")
		}
		if frames[0] == 1 {
			stdout = append(stdout, frames[8:8+n]...)
		}
		frames = frames[8+n:]
	}
	var report struct {
		Results []struct {
			TestID string `json:"test_id"`
		}
	}
	if json.Unmarshal(stdout, &report) != nil || len(report.Results) != 1 || report.Results[0].TestID != "B307" {
		t.Fatal("actual Bandit evidence missing")
	}
	status, _ = request("broker", "DELETE", "/containers/"+id+"?force=1&v=1", nil)
	if status != 204 {
		t.Fatal("remove unconfirmed", status)
	}
	status, _ = request("observer", "GET", "/containers/"+id+"/json", nil)
	if status != 404 {
		t.Fatal("child absence unconfirmed", status)
	}
	checks = append(checks, "exact tracked-ID lifecycle and SDK wait", "real guarded offline Bandit B307", "observer exact-ID absence")
	status, _ = request("broker", "POST", "/containers/"+id+"/start", nil)
	if status != 403 {
		t.Fatal("late start accepted", status)
	}
	checks = append(checks, "late start after removal denied")
	receipt := map[string]any{"schema_version": "1.0", "checks": checks, "tool": "bandit", "tool_image": images["bandit"], "guard_digest": scanners.Hash(guardBytes), "finding_tier": "T0", "controller_bound": false, "all_engine_writes_mediated": false, "cleanup_release_authorized": false, "public_beta": "NO-GO"}
	evidence, _ := json.MarshalIndent(receipt, "", "  ")
	if e = os.WriteFile(filepath.Join(root, "acceptance.json"), append(evidence, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	t.Log("isolated engine authorization checks passed; cleanup release remains unavailable")
}
