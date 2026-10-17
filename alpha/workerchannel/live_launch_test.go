//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func liveClientSample(t *testing.T) (scanevidence.VerifierIdentity, scanevidence.LiveLaunchRecord) {
	t.Helper()
	b, e := os.ReadFile("../../contracts/samples/ScannerLiveLaunchRecordV1.json")
	if e != nil {
		t.Fatal(e)
	}
	var r scanevidence.LiveLaunchRecord
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("synthetic sample")
	}
	now := time.Now().UTC()
	c := &r.Document.Context.Document
	c.Observed = now.Format(time.RFC3339Nano)
	c.LeaseUntil = now.Add(12 * time.Second).Format(time.RFC3339)
	c.Deadline = now.Add(time.Minute).Format(time.RFC3339)
	for i := range c.Workspaces {
		c.Workspaces[i].Document.Deadline = c.Deadline
	}
	for i := range c.Launches {
		c.Launches[i].Document.Deadline = c.Deadline
	}
	resealVerifierContext(&r.Document.Context)
	v := scanevidence.VerifierIdentity{Schema: "1.0", Role: scanevidence.CleanupObserverRole, ID: c.Verifier, Owner: c.Owner, Engine: c.Engine, Registry: c.Registry, State: "active", Created: now.Add(-time.Minute).Format(time.RFC3339Nano), Expires: now.Add(time.Minute).Format(time.RFC3339)}
	return v, r
}
func TestLiveLaunchClientChallengesAndRejectsStaleOrInflatedReplies(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-challenge", "wrong-name", "stale", "expired", "authority", "cancel", "duplicate", "alias", "unknown", "null", "oversize", "withdrawn"} {
		t.Run(kind, func(t *testing.T) {
			v, record := liveClientSample(t)
			calls := 0
			base, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/internal/v1/scanner/verifier/identity" {
					json.NewEncoder(w).Encode(v)
					return
				}
				if r.URL.Path != "/internal/v1/scanner/verifier/live-launch" {
					t.Error("client attempted another operation")
					w.WriteHeader(403)
					return
				}
				calls++
				var in struct {
					Container string `json:"container_name"`
					Challenge string `json:"challenge"`
				}
				if json.NewDecoder(r.Body).Decode(&in) != nil || in.Container != record.Document.Container || len(in.Challenge) != 32 {
					t.Error("request identity or challenge missing")
				}
				out := record
				out.Document.Challenge = in.Challenge
				switch kind {
				case "wrong-challenge":
					out.Document.Challenge = strings.Repeat("d", 32)
				case "wrong-name":
					out.Document.Container = "aegis-scan-" + strings.Repeat("d", 32)
				case "stale":
					out.Document.Context.Document.Observed = time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
				case "expired":
					out.Document.Context.Document.LeaseUntil = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
				case "authority":
					out.Document.EngineAuthorized = true
				case "cancel":
					out.Document.Context.Document.CancelRequested = true
				}
				resealVerifierContext(&out.Document.Context)
				body, _ := json.Marshal(out.Document)
				out.Digest = source.Hash(body)
				wire, _ := json.Marshal(out)
				switch kind {
				case "duplicate":
					wire = []byte(strings.Replace(string(wire), `"challenge":`, `"challenge":"wrong","challenge":`, 1))
				case "alias":
					wire = []byte(strings.Replace(string(wire), `"challenge":`, `"Challenge":`, 1))
				case "unknown":
					wire = []byte(strings.Replace(string(wire), `"document":{`, `"document":{"unknown":true,`, 1))
				case "null":
					wire = []byte(strings.Replace(string(wire), `"live_lease_observed":true`, `"live_lease_observed":null`, 1))
				case "oversize":
					wire = []byte(strings.Repeat(" ", 65537))
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(wire)
			}))
			client, e := NewVerifier(base.socket, cred, v.Owner, v.ID, v.Engine, v.Registry, record.Document.Context.Document.Lock)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			if kind == "withdrawn" {
				os.Remove(cred)
			}
			_, e = client.LiveLaunch(context.Background(), record.Document.Container)
			if (e == nil) != (kind == "valid") {
				t.Fatal("unexpected live client acceptance", e)
			}
			if kind == "withdrawn" && calls != 0 {
				t.Fatal("withdrawn capability reached live endpoint")
			}
		})
	}
}

// Touch the existing path validation before any live request, rather than
// treating an alternate credential file as an equivalent authority.
func TestLiveLaunchClientRejectsMalformedNameBeforeIO(t *testing.T) {
	v, r := liveClientSample(t)
	base, cred := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid name reached channel") }))
	client, e := NewVerifier(base.socket, cred, v.Owner, v.ID, v.Engine, v.Registry, r.Document.Context.Document.Lock)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	for _, name := range []string{"", "../container", "aegis-scan-ABC", r.Document.Container + "?x=1", filepath.Join("/tmp", r.Document.Container)} {
		if _, e = client.LiveLaunch(context.Background(), name); e == nil {
			t.Fatal("invalid name accepted")
		}
	}
}
