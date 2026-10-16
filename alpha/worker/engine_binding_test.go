//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package worker

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoundWorkerChecksOperatorRegistryBeforeClaimAndEngineAccess(t *testing.T) {
	for _, kind := range []string{"valid-idle", "missing", "registry", "wrong-engine", "no-journal", "missing-journal-binding", "missing-journal-dir", "changed-journal", "wrong-journal-root", "pending-journal", "broker-binding-missing", "broker-id-mismatch", "valid-broker-idle"} {
		t.Run(kind, func(t *testing.T) {
			root, e := os.MkdirTemp("/tmp", "aeb-")
			if e != nil {
				t.Fatal(e)
			}
			root, _ = filepath.EvalSymlinks(root)
			defer os.RemoveAll(root)
			os.Mkdir(filepath.Join(root, "tools"), 0700)
			os.WriteFile(filepath.Join(root, "tools/scanners.lock.json"), []byte("trusted lock bytes"), 0600)
			asset := filepath.Join(root, "assets")
			os.Mkdir(asset, 0700)
			credential := filepath.Join(root, "credential")
			os.WriteFile(credential, []byte(strings.Repeat("a", 64)+"\n"), 0600)
			socket := filepath.Join(root, "worker.sock")
			listener, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			os.Chmod(socket, 0600)
			workspace := filepath.Join(root, "workspace")
			registry := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + workspace + "\n" + fmt.Sprint(os.Geteuid())))
			if kind == "registry" {
				registry = source.Hash([]byte("different"))
			}
			engineSocket := filepath.Join(root, "engine.sock")
			engineListener, err := net.Listen("unix", engineSocket)
			if err != nil {
				t.Fatal(err)
			}
			engineCalls := make(chan string, 4)
			engineServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				engineCalls <- r.URL.Path
				if r.Method != "GET" || r.URL.Path != "/v1.55/info" {
					t.Error("unexpected engine request")
					w.WriteHeader(403)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"ID":"fixture-engine","OSType":"linux","Architecture":"arm64"}`))
			})}
			go engineServer.Serve(engineListener)
			defer engineServer.Close()
			t.Setenv("DOCKER_HOST", "unix://"+engineSocket)
			t.Setenv("DOCKER_CONTEXT", "")
			engineDigest := source.Hash([]byte("unix://" + engineSocket + "\nfixture-engine"))
			if kind == "wrong-engine" {
				engineDigest = source.Hash([]byte("wrong"))
			}
			d := scanevidence.EngineBinding{Schema: "1.0", Owner: "owner-a", Engine: engineDigest, Registry: registry, Created: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
			b, _ := json.Marshal(d)
			binding := scanevidence.EngineBindingRecord{Digest: source.Hash(b), Document: d}
			journalPath := filepath.Join(root, "journal")
			journal, e := enginejournal.Open(journalPath, engineDigest)
			if e != nil {
				t.Fatal(e)
			}
			observed := journal.Observe()
			if kind == "pending-journal" {
				if _, e = journal.Begin("aegis-scan-"+strings.Repeat("a", 32), source.Hash([]byte("fixture"))); e != nil {
					t.Fatal(e)
				}
			}
			journal.Close()
			jd := scanevidence.JournalBinding{Schema: "1.0", Owner: "owner-a", EngineBinding: binding.Digest, Root: source.Hash([]byte("aegis-scanner-engine-journal-root-v1\n" + journalPath + "\n" + fmt.Sprint(os.Geteuid()))), Namespace: observed.Namespace, Created: time.Now().UTC().Format(time.RFC3339Nano)}
			if kind == "changed-journal" {
				jd.Namespace = source.Hash([]byte("other"))
			}
			if kind == "wrong-journal-root" {
				jd.Root = source.Hash([]byte("other"))
			}
			raw, _ := json.Marshal(jd)
			journalBinding := scanevidence.JournalBindingRecord{Digest: source.Hash(raw), Document: jd}
			if kind == "missing-journal-dir" {
				os.RemoveAll(journalPath)
			}
			brokerDoc := scanevidence.BrokerBinding{Schema: "1.0", Owner: "owner-a", Worker: "broker-a", Journal: journalBinding.Digest, Created: time.Now().UTC().Format(time.RFC3339Nano)}
			if kind == "broker-id-mismatch" {
				brokerDoc.Worker = "other"
			}
			brokerRaw, _ := json.Marshal(brokerDoc)
			brokerBinding := scanevidence.BrokerBindingRecord{Digest: source.Hash(brokerRaw), Document: brokerDoc}
			calls := make(chan string, 4)
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls <- r.URL.Path
				switch r.URL.Path {
				case "/internal/v1/scanner/engine-binding":
					if kind == "missing" {
						w.WriteHeader(404)
						w.Write([]byte(`{}`))
						return
					}
					json.NewEncoder(w).Encode(binding)
				case "/internal/v1/scanner/engine-journal-binding":
					if kind == "missing-journal-binding" {
						w.WriteHeader(404)
						w.Write([]byte(`{}`))
						return
					}
					json.NewEncoder(w).Encode(journalBinding)
				case "/internal/v1/scanner/engine-broker-binding":
					if kind == "broker-binding-missing" {
						w.WriteHeader(404)
						w.Write([]byte(`{}`))
						return
					}
					json.NewEncoder(w).Encode(brokerBinding)
				case "/internal/v1/scanner/claim":
					w.WriteHeader(204)
				default:
					t.Error("unexpected authority/engine action")
					w.WriteHeader(404)
				}
			})}
			go server.Serve(listener)
			defer server.Close()
			cfg := Config{RequireEngineBinding: true, Socket: socket, Credential: credential, Owner: "owner-a", SourceRoot: root, AssetRoot: asset, WorkspaceRoot: workspace, EngineJournalRoot: filepath.Join(root, "journal")}
			if kind == "no-journal" {
				cfg.EngineJournalRoot = ""
			}
			if strings.HasPrefix(kind, "broker-") || kind == "valid-broker-idle" {
				cfg.ExpectedBrokerID = "broker-a"
			}
			report, e := cfg.RunOnce(context.Background())
			if kind == "valid-idle" || kind == "valid-broker-idle" {
				if e != nil || report.State != "no_job" {
					t.Fatal(report, e)
				}
			} else if e == nil || report.State != "not_claimed" {
				t.Fatal("unprovisioned claim", report, e)
			}
			count := len(calls)
			expected := 2
			if kind == "missing" || kind == "registry" {
				expected = 1
			}
			if kind == "valid-idle" || kind == "valid-broker-idle" {
				expected = 3
			}
			if kind == "no-journal" {
				expected = 0
			}
			if kind == "broker-binding-missing" || kind == "broker-id-mismatch" {
				expected = 3
			}
			if kind == "valid-broker-idle" {
				expected = 4
			}
			if count != expected {
				t.Fatal(count, expected)
			}
			engineCount := 0
			if kind == "valid-idle" || kind == "valid-broker-idle" || kind == "wrong-engine" {
				engineCount = 1
			}
			if len(engineCalls) != engineCount {
				t.Fatal("unexpected engine metadata count", len(engineCalls), engineCount)
			}
			if _, e = os.Stat(workspace); !os.IsNotExist(e) {
				t.Fatal("workspace allocated before a valid claim")
			}
		})
	}
}
