//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/connector"
	"aegis.local/controller/internal/store"
)

// This test uses the compiled bridge, the real API handler and a disposable
// database. The only incident data are fixed synthetic records inserted here.
func TestPackagedDesktopBridgeJourney(t *testing.T) {
	for _, fixture := range []struct {
		name string
		mtls bool
	}{{"console", false}, {"mutual-tls", true}} {
		t.Run(fixture.name, func(t *testing.T) { runDesktopBridgeJourney(t, fixture.mtls) })
	}
}
func runDesktopBridgeJourney(t *testing.T, mtls bool) {
	binary := os.Getenv("AEGIS_TEST_MCP_PATH")
	if binary == "" {
		t.Skip("run make desktop-verify to test the compiled bridge")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("bridge path must be absolute")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, "desktop")
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "acceptance.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	const password = "a fixture-only owner passphrase"
	a := auth.New(s)
	if err = a.Enroll(a.Bootstrap, password); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO incidents(id,summary,opened_at,state,severity,confidence)
 VALUES('inc-fixture','Synthetic incident','2026-10-17T12:45:00Z','open','medium','high');
 INSERT INTO events(id,at,request,source_key,document)
 VALUES('ev-fixture','2026-10-17T12:45:00Z','private-request','fixture-source',
 '{"decision":"blocked","rule_ids":["942100"],"client_key":"PRIVATE_FIXTURE_CANARY"}');
 INSERT INTO incident_events(incident,event) VALUES('inc-fixture','ev-fixture')`); err != nil {
		t.Fatal(err)
	}
	app := &Server{S: s, A: a, Assets: t.TempDir(), Connectors: &connector.Registry{S: s}}
	handler := app.Handler()
	var simulateLostRenewalReceipt atomic.Bool
	withLostRenewalReceipt := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/desktop/renew" && simulateLostRenewalReceipt.CompareAndSwap(true, false) {
				recorded := httptest.NewRecorder()
				handler.ServeHTTP(recorded, r)
				if recorded.Code == http.StatusOK {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(recorded.Code)
				return
			}
			handler.ServeHTTP(w, r)
		})
	}
	server := httptest.NewServer(withLostRenewalReceipt(handler))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	hc := server.Client()
	request := func(method, path string, payload any, cookie *http.Cookie, csrf string, want int) (*http.Response, []byte) {
		t.Helper()
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		r, e := http.NewRequestWithContext(ctx, method, server.URL+"/api/v1"+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", csrf)
		}
		resp, e := hc.Do(r)
		if e != nil {
			t.Fatalf("fixture request %s failed: %v", path, e)
		}
		defer resp.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
		if e != nil || len(raw) > 65536 || resp.StatusCode != want {
			t.Fatalf("unexpected response to %s: HTTP %d, expected %d", path, resp.StatusCode, want)
		}
		return resp, raw
	}
	login, raw := request("POST", "/auth/login", map[string]string{"password": password}, nil, "", 200)
	var credentials struct {
		CSRF string `json:"csrf_token"`
	}
	decodeDesktopAcceptance(t, raw, &credentials)
	cookies := login.Cookies()
	if len(cookies) != 1 || credentials.CSRF == "" {
		t.Fatal("owner login did not return session")
	}
	owner := func(method, path string, value any, want int) []byte {
		t.Helper()
		_, raw := request(method, path, value, cookies[0], credentials.CSRF, want)
		return raw
	}
	var invitation struct {
		Pairing connector.Pairing `json:"pairing"`
		Code    string            `json:"invite_code"`
	}
	decodeDesktopAcceptance(t, owner("POST", "/desktop/pairing", map[string]any{"name": "Synthetic desktop", "lifetime_minutes": 15, "allow_analysis_draft": true}, 201), &invitation)
	if invitation.Pairing.ID == "" || invitation.Code == "" {
		t.Fatal("missing invitation")
	}
	bridgeURL := server.URL
	var env []string
	if mtls {
		bridgeURL, env = desktopTLSFixture(t, withLostRenewalReceipt(app.DesktopTransportHandler()), private, cookies[0])
	}
	env = append(env, "AEGIS_URL="+bridgeURL)
	if account := os.Getenv("AEGIS_TEST_KEYCHAIN_ACCOUNT"); account != "" {
		if mtls {
			account += "-mtls"
		}
		env = append(env, "AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT="+account, "HOME="+os.Getenv("HOME"))
	} else {
		env = append(env, "AEGIS_CONNECTOR_TOKEN_FILE="+filepath.Join(private, "token"))
	}
	pairing := exec.CommandContext(ctx, binary, "pair")
	pairing.Env = env
	pairing.Stdin = strings.NewReader(invitation.Pairing.ID + ":" + invitation.Code + "\n")
	pairing.Stdout = io.Discard
	stderr, err := pairing.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = pairing.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	t.Cleanup(func() {
		if !joined {
			_ = pairing.Process.Kill()
			_ = pairing.Wait()
		}
	})
	scan := bufio.NewScanner(stderr)
	fingerprint := ""
	for scan.Scan() {
		if value, ok := strings.CutPrefix(scan.Text(), "Device fingerprint: "); ok {
			fingerprint = value
			break
		}
	}
	if len(fingerprint) != 20 {
		t.Fatal("bridge did not display a fingerprint")
	}
	owner("POST", "/desktop/pairing/"+invitation.Pairing.ID, map[string]any{"approve": true, "fingerprint": fingerprint}, 200)
	if _, err = io.Copy(io.Discard, stderr); err != nil {
		t.Fatal("bridge status unreadable")
	}
	err = pairing.Wait()
	joined = true
	if err != nil {
		t.Fatalf("compiled bridge could not finish pairing: %v", err)
	}
	t.Log("compiled bridge paired through verified owner fingerprint")

	mcp := exec.CommandContext(ctx, binary)
	mcp.Env = env
	mcp.Stderr = io.Discard
	stdin, err := mcp.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := mcp.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = mcp.Start(); err != nil {
		t.Fatal(err)
	}
	bridgeJoined := false
	t.Cleanup(func() {
		if !bridgeJoined {
			_ = mcp.Process.Kill()
			_ = mcp.Wait()
		}
	})
	encoder, decoder := json.NewEncoder(stdin), json.NewDecoder(stdout)
	sequence := 0
	rpc := func(method string, params any, dest any) bool {
		t.Helper()
		sequence++
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": sequence, "method": method, "params": params}); err != nil {
			t.Fatal("bridge input unavailable")
		}
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if decoder.Decode(&response) != nil || response.ID != sequence || len(response.Error) != 0 {
			t.Fatalf("bridge protocol failed for %s", method)
		}
		if method != "tools/call" {
			decodeDesktopAcceptance(t, response.Result, dest)
			return true
		}
		var result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		decodeDesktopAcceptance(t, response.Result, &result)
		if result.IsError {
			return false
		}
		if len(result.Content) != 1 {
			t.Fatal("bridge returned unexpected content")
		}
		text := result.Content[0].Text
		_, body, ok := strings.Cut(text, "\n\n")
		if !ok || !strings.HasPrefix(text, "UNTRUSTED DATA FROM AEGIS") {
			t.Fatal("bridge omitted evidence notice")
		}
		decodeDesktopAcceptance(t, []byte(body), dest)
		return true
	}
	tool := func(name string, args any, dest any) bool {
		t.Helper()
		return rpc("tools/call", map[string]any{"name": name, "arguments": args}, dest)
	}
	// A request before the handshake must not reach the controller. The
	// transcript then asks for a future revision and accepts our declared one.
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": "before-init", "method": "tools/call", "params": map[string]any{"name": "aegis_status", "arguments": map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	var denied struct {
		ID    string `json:"id"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if decoder.Decode(&denied) != nil || denied.ID != "before-init" || denied.Error.Code != -32002 {
		t.Fatal("bridge allowed a tool before MCP initialization")
	}
	var hello map[string]any
	rpc("initialize", map[string]any{"protocolVersion": "2099-01-01", "clientInfo": map[string]string{"name": "fixture", "version": "1.0"}, "capabilities": map[string]any{}}, &hello)
	if hello["protocolVersion"] != "2025-06-18" {
		t.Fatal("bridge advertised an unsupported MCP version")
	}
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": "before-ready", "method": "tools/list", "params": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if decoder.Decode(&denied) != nil || denied.ID != "before-ready" || denied.Error.Code != -32002 {
		t.Fatal("bridge allowed tools before initialized notification")
	}
	if err = encoder.Encode(map[string]string{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		t.Fatal(err)
	}
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	rpc("tools/list", map[string]string{}, &tools)
	advertised := map[string]bool{}
	for _, v := range tools.Tools {
		advertised[v.Name] = true
	}
	for _, name := range []string{"aegis_status", "aegis_get_handoff", "aegis_submit_draft_analysis", "aegis_get_draft_status"} {
		if !advertised[name] {
			t.Fatalf("missing bridge tool %s", name)
		}
	}
	if len(advertised) != 4 {
		t.Fatal("paired bridge advertised tools outside its authenticated scope")
	}
	var status map[string]any
	if !tool("aegis_status", map[string]string{}, &status) || status["authenticated"] != true {
		t.Fatal("paired bridge failed status check")
	}
	if tool("aegis_list_sites", map[string]string{}, &status) {
		t.Fatal("paired device reached general site list")
	}
	var preview connector.HandoffPreview
	decodeDesktopAcceptance(t, owner("GET", "/desktop/handoff-preview?incident_id=inc-fixture", nil, 200), &preview)
	if len(preview.Bundle.Observations) != 1 {
		t.Fatal("unexpected synthetic evidence")
	}
	var handoff connector.Handoff
	decodeDesktopAcceptance(t, owner("POST", "/desktop/handoffs", map[string]any{
		"incident_id": "inc-fixture", "connector_id": invitation.Pairing.ID, "preview_digest": preview.Digest,
		"approve_redacted_export": true, "allow_analysis_draft": true,
	}, 201), &handoff)
	var bundle connector.HandoffBundle
	args := map[string]string{"handoff_id": handoff.ID}
	// A notification-shaped tool call cannot consume the owner's one-use bundle.
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "tools/call", "params": map[string]any{"name": "aegis_get_handoff", "arguments": args}}); err != nil {
		t.Fatal(err)
	}
	if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "method": "tools/call", "params": map[string]any{"name": "aegis_get_handoff", "arguments": args}}); err != nil {
		t.Fatal(err)
	}
	if decoder.Decode(&denied) != nil || denied.Error.Code != -32600 {
		t.Fatal("bridge accepted a null request ID")
	}
	if !tool("aegis_get_handoff", args, &bundle) || domainDesktopAcceptance(t, bundle) != domainDesktopAcceptance(t, preview.Bundle) {
		t.Fatal("delivered bundle differs from owner preview")
	}
	if tool("aegis_get_handoff", args, &bundle) {
		t.Fatal("single-use handoff was returned again")
	}
	t.Log("compiled bridge observed only the approved redacted bundle")
	input := map[string]any{
		"idempotency_key": "fixture-packaged-draft-v1", "incident_id": "inc-fixture", "handoff_id": handoff.ID, "client_label": "Fixture desktop",
		"claims":      []connector.DraftClaim{{Claim: "The retained gateway record was blocked.", Kind: "observation", Sources: []string{bundle.Observations[0].ID}}},
		"limitations": []string{"Synthetic evidence only."}, "proposed_steps": []connector.DraftStep{},
	}
	var receipt, replay connector.DraftStatus
	if !tool("aegis_submit_draft_analysis", input, &receipt) || receipt.ID == "" || receipt.State != "unverified" {
		t.Fatal("bridge did not return an unverified draft")
	}
	if !tool("aegis_submit_draft_analysis", input, &replay) || replay != receipt {
		t.Fatal("retry changed the draft receipt")
	}
	var listing struct {
		Items []connector.OwnerDraft `json:"items"`
	}
	decodeDesktopAcceptance(t, owner("GET", "/desktop/drafts?incident_id=inc-fixture", nil, 200), &listing)
	if len(listing.Items) != 1 || listing.Items[0].ID != receipt.ID || listing.Items[0].BundleDigest != preview.Digest {
		t.Fatal("owner did not see exact draft provenance")
	}
	owner("POST", "/desktop/drafts/"+receipt.ID+"/dismiss", map[string]bool{}, 200)
	if !tool("aegis_get_draft_status", map[string]string{"draft_id": receipt.ID}, &replay) || replay.State != "dismissed" {
		t.Fatal("bridge could not observe owner dismissal")
	}
	owner("POST", "/connectors/"+invitation.Pairing.ID+"/renew", map[string]bool{}, 200)
	simulateLostRenewalReceipt.Store(true)
	rotation := exec.CommandContext(ctx, binary, "renew")
	rotation.Env = env
	rotation.Stdout = io.Discard
	rotation.Stderr = io.Discard
	if err = rotation.Run(); err != nil || simulateLostRenewalReceipt.Load() {
		t.Fatalf("bridge could not recover committed renewal: %v", err)
	}
	if tool("aegis_status", map[string]string{}, &status) {
		t.Fatal("already-running bridge kept using its retired credential")
	}
	// Reopen a stdio process with the rotated credential.
	checkFreshStatus := func(want bool) {
		t.Helper()
		fresh := exec.CommandContext(ctx, binary)
		fresh.Env = env
		fresh.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"aegis_status","arguments":{}}}
`)
		data, e := fresh.Output()
		if e != nil {
			t.Fatal("could not check restarted bridge")
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		var init json.RawMessage
		var reply struct {
			ID     int `json:"id"`
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if dec.Decode(&init) != nil || dec.Decode(&reply) != nil || reply.ID != 2 || reply.Result.IsError == want || len(reply.Result.Content) != 1 {
			t.Fatal("restarted bridge status did not match credential state")
		}
		if want {
			_, body, ok := strings.Cut(reply.Result.Content[0].Text, "\n\n")
			if !ok {
				t.Fatal("restarted bridge omitted connector status")
			}
			var active struct {
				ID    string `json:"connector_id"`
				Scope string `json:"scope"`
			}
			decodeDesktopAcceptance(t, []byte(body), &active)
			if active.ID != invitation.Pairing.ID || active.Scope != connector.PairedScope {
				t.Fatal("renewal changed connector identity or scope")
			}
		}
	}
	checkFreshStatus(true)
	t.Log("compiled bridge recovered a lost rotation response, retired the old token and preserved the connector ID")
	owner("POST", "/connectors/"+invitation.Pairing.ID+"/revoke", map[string]bool{}, 200)
	checkFreshStatus(false)
	if err = stdin.Close(); err != nil {
		t.Fatal(err)
	}
	err = mcp.Wait()
	bridgeJoined = true
	if err != nil {
		t.Fatalf("bridge did not exit cleanly: %v", err)
	}
	if err = s.VerifyAudit(); err != nil {
		t.Fatal("invalid audit chain")
	}
	t.Log("compiled bridge returned one unverified draft, reported dismissal, and lost access on revocation")
}

func decodeDesktopAcceptance(t *testing.T, raw []byte, value any) {
	t.Helper()
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatalf("invalid fixture response: %v", err)
	}
}
func domainDesktopAcceptance(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
