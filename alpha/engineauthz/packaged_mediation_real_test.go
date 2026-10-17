// SPDX-License-Identifier: BUSL-1.1
package engineauthz_test

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/enginetls"
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
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A native CI-only trusted client sends the enumerated unadmitted write surface
// to the actual admitted TLS engine as both the broker and the observer. Every
// routed request must be refused by this plugin; aliases the daemon does not
// route must not succeed either. The fixture separately compares daemon state.
func TestRealPackagedEngineRefusesUnadmittedWrites(t *testing.T) {
	if os.Getenv("AEGIS_PACKAGED_CONTROLLER_GATE_TEST") != "1" || os.Getenv("AEGIS_PACKAGED_ADMISSION_TEST") != "1" {
		t.Skip("explicit disposable admitted engine fixture only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 10001 || os.Getegid() != 10001 {
		t.Fatal("dedicated unprivileged Linux fixture required")
	}
	u, e := url.Parse(os.Getenv("AEGIS_GATE_PROBE_ENDPOINT"))
	if e != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		t.Fatal("fixed private engine endpoint required")
	}
	journal := os.Getenv("AEGIS_GATE_PROBE_JOURNAL")
	if !filepath.IsAbs(journal) || filepath.Base(journal) != "bound-journal" || !strings.HasPrefix(filepath.Base(filepath.Dir(filepath.Dir(journal))), "aegis-packaged-engine-") {
		t.Fatal("separate private plugin journal required")
	}
	images, _, e := engineauthz.ReadLock(os.Getenv("AEGIS_GATE_PROBE_LOCK"))
	if e != nil || images["bandit"] == "" {
		t.Fatal("pinned tools unavailable")
	}
	clients := map[string]*http.Client{}
	for role, variable := range map[string]string{enginetls.Broker: "AEGIS_GATE_PROBE_TLS", enginetls.Observer: "AEGIS_GATE_PROBE_OBSERVER_TLS"} {
		identity, e := enginetls.Load(os.Getenv(variable), role)
		if e != nil {
			t.Fatal("private test client identity unavailable")
		}
		transport := &http.Transport{Proxy: nil, TLSClientConfig: identity.TLS, ResponseHeaderTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
		defer transport.CloseIdleConnections()
		clients[role] = &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	before := journalEntries(t, journal)
	random := func(n int) string {
		b := make([]byte, n)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(b)
	}
	probes := engineauthz.WriteSurface(random(32), random(32), "aegis-scan-"+random(16), images["bandit"])
	refused, routed := 0, 0
	for _, w := range probes {
		if !w.Raw {
			routed++
		}
		for role, client := range clients {
			status, message := send(t, client, u.String(), w)
			if w.Raw {
				// An alias may be refused by the plugin, or never routed to a
				// handler at all (404/301/400). It must never succeed.
				if status < 300 || status >= 500 {
					t.Fatalf("%s alias %s returned %d for %s", w.Class, w.Method, status, role)
				}
				continue
			}
			if status != 403 || !strings.Contains(message, "authorization denied by plugin") || !strings.Contains(message, engineauthz.ErrPolicy.Error()) {
				t.Fatalf("%s %s was not refused by the scanner authorizer for %s (status %d)", w.Class, w.Method, role, status)
			}
			refused++
		}
	}
	if routed < 80 || refused != 2*routed {
		t.Fatalf("write surface unexpectedly small: %d", refused)
	}
	if after := journalEntries(t, journal); !reflect.DeepEqual(before, after) {
		t.Fatal("refused writes reached the plugin mutation journal")
	}
}

func send(t *testing.T, client *http.Client, base string, w engineauthz.WriteProbe) (int, string) {
	t.Helper()
	uri := w.URI
	if !w.Raw {
		uri = "/v1.55" + uri
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var body io.Reader
	if w.Body != "" {
		body = strings.NewReader(w.Body)
	}
	request, e := http.NewRequestWithContext(ctx, w.Method, base+uri, body)
	if e != nil {
		// Fragments and malformed aliases are not sent; that is not a refusal.
		if w.Raw {
			return 400, ""
		}
		t.Fatal("probe request invalid")
	}
	if w.ContentType != "" {
		request.Header.Set("Content-Type", w.ContentType)
	}
	response, e := client.Do(request)
	if e != nil {
		t.Fatalf("%s %s probe unavailable", w.Class, w.Method)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
	var decoded struct{ Message string }
	_ = json.Unmarshal(raw, &decoded)
	return response.StatusCode, decoded.Message
}

func journalEntries(t *testing.T, root string) []string {
	t.Helper()
	names := []string{}
	e := filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(root, path)
		names = append(names, rel+"\x00"+info.Mode().String()+"\x00"+info.ModTime().UTC().Format(time.RFC3339Nano))
		return nil
	})
	if e != nil {
		t.Fatal("plugin journal unreadable")
	}
	return names
}
