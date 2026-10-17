//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package scannerchannelacceptance

import (
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRealWorkspaceReservationPrecedesCaptureAndSurvivesLostAcknowledgement(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "capture_crash", true: "lost_ack"}[lost], func(t *testing.T) {
			f := setup(t)
			j := enqueue(t, f)
			l, e := f.client.Claim(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			parent, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			registry := filepath.Join(parent, "registry")
			manifest := source.Manifest{Schema: "1.0", InputMap: l.Map.Digest, Commit: l.Map.Commit, Files: l.Map.Files}
			for _, file := range manifest.Files {
				manifest.Bytes += file.Size
			}
			b, _ := json.Marshal(manifest)
			var recorded scanevidence.WorkspaceRecord
			session, e := workspace.BeginReserved(registry, func(id string) (string, error) {
				if _, err := os.Lstat(filepath.Join(registry, id)); !os.IsNotExist(err) {
					t.Fatal("run exists before private authorization")
				}
				record, err := f.client.ReserveWorkspace(context.Background(), l, scanevidence.WorkspacePlan{Tool: "bandit", Workspace: id, Registry: source.Hash([]byte("provisioned fixture namespace")), Snapshot: source.Hash(b)})
				if err != nil {
					return "", err
				}
				recorded = record
				rows, err := f.q.Workspaces("owner-a", j.ID)
				if err != nil || len(rows) != 1 || rows[0].Digest != record.Digest {
					t.Fatal("acknowledgement preceded durable commit", err)
				}
				if lost {
					return "", errors.New("simulate acknowledgement lost after commit")
				}
				return record.Digest, nil
			})
			if lost {
				if e == nil {
					t.Fatal("lost ack allocated run")
				}
				entries, e := os.ReadDir(registry)
				if e != nil {
					t.Fatal(e)
				}
				if len(entries) != 1 || entries[0].Name() != ".registry-lock" {
					t.Fatal("lost ack created source workspace")
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				root, e := os.OpenRoot(filepath.Join(f.assetRoot, "fixture"))
				if e != nil {
					t.Fatal(e)
				}
				snapshot, e := source.Capture(context.Background(), root, l.Map, session.Path)
				root.Close()
				if e != nil {
					t.Fatal(e)
				}
				if snapshot.Manifest.Digest != recorded.Document.Plan.Snapshot {
					t.Fatal("captured input escaped reservation")
				}
				session.Preserve() // simulate worker death after capture, before any launch.
			}
			later := time.Now().Add(20 * time.Second)
			f.q.Now = func() time.Time { return later }
			if e = f.q.Reconcile(); e != nil {
				t.Fatal(e)
			}
			assertCleanupHeld(t, f)
			launches, e := f.q.Launches("owner-a", j.ID)
			if e != nil || len(launches) != 0 {
				t.Fatal("capture fabricated scanner execution")
			}
			records, e := f.q.Workspaces("owner-a", j.ID)
			if e != nil || len(records) != 1 || records[0].Digest != recorded.Digest {
				t.Fatal("capture intent lost after expiry")
			}
			recovered, e := workspace.Recover(context.Background(), registry, time.Now().Add(4*time.Minute), nil)
			if e != nil {
				t.Fatal(e)
			}
			if lost && recovered.Removed != 0 || !lost && recovered.Removed != 1 {
				t.Fatal("wrong local orphan recovery", recovered)
			}
			assertCleanupHeld(t, f) // local recovery cannot release controller admission.
		})
	}
}
