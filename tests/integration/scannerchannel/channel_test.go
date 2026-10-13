//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// These integration tests connect the real alpha client to the real controller
// handler, enrollment registry and migrated SQLite queue over a private socket.
package scannerchannelacceptance

import (
	"aegis.local/alpha/workerchannel"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/controller/internal/scanqueue"
	"aegis.local/controller/internal/scantransport"
	"aegis.local/controller/internal/store"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	client             *workerchannel.Client
	q                  *scanqueue.Queue
	auth               *scannerauth.Registry
	s                  *store.Store
	in                 scanqueue.Input
	credential, socket string
	assetRoot          string
}

func setup(t *testing.T) fixture {
	return setupSource(t, []byte("# static source; never executed\n"))
}

func setupSource(t *testing.T, content []byte) fixture {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if _, e = s.DB.Exec("INSERT INTO owners VALUES('owner-a','test',?),('owner-b','test',?)", domain.Now(), domain.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO settings VALUES('repository_mount_owner','owner-a')"); e != nil {
		t.Fatal(e)
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "fixture"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "fixture", "query.py"), content, 0600); e != nil {
		t.Fatal(e)
	}
	reg, e := repository.Open(s, root)
	if e != nil {
		t.Fatal(e)
	}
	defer reg.Root.Close()
	repo, e := reg.Connect("owner-a", "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("/tmp", "asci-")
	if e != nil {
		t.Fatal(e)
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	a := &scannerauth.Registry{S: s}
	cred := filepath.Join(dir, "worker.credential")
	if _, e = a.EnrollFile("owner-a", "worker-a", 60, cred); e != nil {
		t.Fatal(e)
	}
	digest, pins, e := scantransport.LoadPins("../../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	q := &scanqueue.Queue{S: s, LockDigest: digest, Pins: pins}
	socket := filepath.Join(dir, "worker.sock")
	listener, e := scantransport.Listen(socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: (&scantransport.Server{Q: q, Auth: a}).Handler()}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	c, e := workerchannel.New(socket, cred, "owner-a", q.LockDigest)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return fixture{c, q, a, s, scanqueue.Input{Schema: "1.0", App: "app_demo", Repository: repo.ID, MapDigest: repo.MapDigest, Mode: "repo_offline", Tools: []string{"bandit"}, Duration: 120}, cred, socket, root}
}
func enqueue(t *testing.T, f fixture) scanqueue.Job {
	t.Helper()
	j, e := f.q.Enqueue("owner-a", "interop-request-key", f.in)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func assertCleanupHeld(t *testing.T, f fixture) {
	t.Helper()
	var n int
	if e := f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch WHERE state='cleanup_required'").Scan(&n); e != nil || n != 1 {
		t.Fatal("uncertain cleanup admission was released")
	}
}
func TestRealClientControllerLifecycle(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	w, e := f.client.Identity(ctx)
	if e != nil || w.ID != "worker-a" || w.Owner != "owner-a" {
		t.Fatal("real worker identity failed", e)
	}
	if _, e = f.client.Claim(ctx); !errors.Is(e, workerchannel.ErrEmpty) {
		t.Fatal("real empty queue not distinguished", e)
	}
	j := enqueue(t, f)
	l, e := f.client.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if l.Job.ID != j.ID || l.Job.RequestDigest != j.RequestDigest || l.Map.Digest != j.Input.MapDigest || l.Map.SourceRef != "mounted-asset:fixture" {
		t.Fatal("claim identity mismatch")
	}
	if e = f.client.Guard(ctx, l); e != nil {
		t.Fatal(e)
	}
	if e = f.client.Fail(ctx, l, "SOURCE_CAPTURE_FAILED"); e != nil {
		t.Fatal(e)
	}
	if e = f.client.Fail(ctx, l, "SOURCE_CAPTURE_FAILED"); e != nil {
		t.Fatal("real failure replay failed", e)
	}
	if e = f.client.Fail(ctx, l, "TOOL_UNAVAILABLE"); e == nil {
		t.Fatal("conflicting failure replay accepted")
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "tool_error" || got.Error != "SOURCE_CAPTURE_FAILED" {
		t.Fatal("failure not persisted")
	}
	assertCleanupHeld(t, f)
	if _, e = f.client.Claim(ctx); e == nil || errors.Is(e, workerchannel.ErrEmpty) {
		t.Fatal("cleanup occupancy hidden as empty queue")
	}
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	rows, e := f.s.DB.Query("SELECT document FROM audit")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var document string
		if rows.Scan(&document) != nil {
			t.Fatal("audit read failed")
		}
		if strings.Contains(document, l.Token) {
			t.Fatal("lease capability leaked into audit")
		}
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(l)
	if strings.Contains(string(b), l.Token) {
		t.Fatal("general lease JSON leaked capability")
	}
}
func TestRealRevocationStopsGuardAndRetainsAdmission(t *testing.T) {
	f := setup(t)
	j := enqueue(t, f)
	l, e := f.client.Claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.auth.Revoke("owner-a", "worker-a"); e != nil {
		t.Fatal(e)
	}
	if e = f.client.Guard(context.Background(), l); e == nil {
		t.Fatal("revoked worker renewed execution")
	}
	if _, e = f.client.Identity(context.Background()); e == nil {
		t.Fatal("revoked worker authenticated")
	}
	assertCancellationPending(t, f, j.ID)
	later := time.Now().Add(20 * time.Second)
	f.q.Now = func() time.Time { return later }
	if e = f.q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" || got.Error != "WORKER_REVOKED" {
		t.Fatal("revocation did not reconcile honestly")
	}
	assertCleanupHeld(t, f)
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestRealOwnerCancellationStopsGuard(t *testing.T) {
	f := setup(t)
	j := enqueue(t, f)
	l, e := f.client.Claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.q.Cancel("owner-a", j.ID); e != nil {
		t.Fatal(e)
	}
	if e = f.client.Guard(context.Background(), l); e == nil {
		t.Fatal("owner cancellation ignored")
	}
	assertCancellationPending(t, f, j.ID)
	later := time.Now().Add(20 * time.Second)
	f.q.Now = func() time.Time { return later }
	if e = f.q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" || got.Error != "OWNER_CANCELLED" {
		t.Fatal("cancellation did not persist")
	}
	assertCleanupHeld(t, f)
}
func TestRealExpiredLeaseCannotRevive(t *testing.T) {
	f := setup(t)
	j := enqueue(t, f)
	l, e := f.client.Claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	// Set only the authoritative controller clock past the original lease. No
	// sleeps, expired observation handles or retries of external execution.
	later := time.Now().Add(20 * time.Second)
	f.q.Now = func() time.Time { return later }
	if e = f.client.Guard(context.Background(), l); e == nil {
		t.Fatal("expired controller lease renewed")
	}
	if e = f.q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	got, e := f.q.Get("owner-a", j.ID)
	if e != nil || got.State != "timeout" {
		t.Fatal("expired worker falsely succeeded")
	}
	assertCleanupHeld(t, f)
}
func TestRealPinsAndOwnerMismatchRefuseClaim(t *testing.T) {
	for _, change := range []string{"owner", "pins"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			enqueue(t, f)
			owner, lock := "owner-a", f.q.LockDigest
			if change == "owner" {
				owner = "owner-b"
			} else {
				lock = domain.Hash([]byte("other pins"))
			}
			c, e := workerchannel.New(f.socket, f.credential, owner, lock)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if _, e = c.Claim(context.Background()); e == nil {
				t.Fatal("mismatched real claim accepted")
			}
			// The controller has issued a lease before the client can reject its binding.
			// Admission stays occupied and must expire/reconcile, never auto-retry.
			var n int
			if e = f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&n); e != nil || n != 1 {
				t.Fatal("rejected claim lost durable admission")
			}
		})
	}
}

func assertCancellationPending(t *testing.T, f fixture, id string) {
	t.Helper()
	j, e := f.q.Get("owner-a", id)
	if e != nil || j.State != "running" || !j.CancelRequested {
		t.Fatal("authority withdrawal did not persist pending cancellation")
	}
	var count int
	if e = f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch WHERE state='active'").Scan(&count); e != nil || count != 1 {
		t.Fatal("pending cancellation lost admission")
	}
}

func TestRealKeeperCancelsOnWorkerRevocation(t *testing.T) {
	f := setup(t)
	enqueue(t, f)
	l, e := f.client.Claim(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	taskStopped := false
	e = f.client.RunWithLease(ctx, l, func(run context.Context) error {
		if e := f.auth.Revoke("owner-a", "worker-a"); e != nil {
			return e
		}
		<-run.Done()
		taskStopped = true
		return nil
	})
	if !errors.Is(e, workerchannel.ErrAuthority) || !taskStopped {
		t.Fatal("real role revocation did not cancel and join task")
	}
	var count int
	if e = f.s.DB.QueryRow("SELECT count(*) FROM scanner_dispatch").Scan(&count); e != nil || count != 1 {
		t.Fatal("keeper falsely released process cleanup")
	}
	if e = f.s.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
