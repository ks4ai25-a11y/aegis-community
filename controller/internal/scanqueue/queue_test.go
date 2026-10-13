// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/store"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Queue, Input, string) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "scan.db")
	s, e := store.Open(db)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	if _, e = s.DB.Exec("INSERT INTO owners VALUES('owner-a','test',?),('owner-b','test',?)", domain.Now(), domain.Now()); e != nil {
		t.Fatal(e)
	}
	// Repository mounts must be durably bound before a second owner exists.
	if _, e = s.DB.Exec("INSERT INTO settings VALUES('repository_mount_owner','owner-a')"); e != nil {
		t.Fatal(e)
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(root, "fixture"), 0700)
	os.WriteFile(filepath.Join(root, "fixture", "query.py"), []byte("static only"), 0600)
	r, e := repository.Open(s, root)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Root.Close()
	repo, e := r.Connect("owner-a", "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	q := &Queue{S: s, LockDigest: domain.Hash([]byte("trusted-tool-lock")), Now: func() time.Time { return now }}
	return q, Input{"1.0", "app_demo", repo.ID, repo.MapDigest, "repo_offline", []string{"bandit", "semgrep_ce"}, 120}, db
}
func TestOwnerIdempotencyAndRestart(t *testing.T) {
	q, in, db := fixture(t)
	j, e := q.Enqueue("owner-a", "stable-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	in.Tools[0] = "gitleaks"
	if j.Input.Tools[0] != "bandit" {
		t.Fatal("caller changed stored input")
	}
	in = j.Input
	same, e := q.Enqueue("owner-a", "stable-key-001", in)
	if e != nil || same.ID != j.ID {
		t.Fatal(same, e)
	}
	changed := in
	changed.Duration = 119
	if _, e = q.Enqueue("owner-a", "stable-key-001", changed); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, e = q.Get("owner-b", j.ID); e != sql.ErrNoRows {
		t.Fatal("cross-owner job exposed", e)
	}
	if _, e = q.Enqueue("owner-b", "stable-key-002", in); e != sql.ErrNoRows {
		t.Fatal("cross-owner repository accepted", e)
	}
	if e = q.Cancel("owner-b", j.ID); e != sql.ErrNoRows {
		t.Fatal("cross-owner cancelled job", e)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
	if e = q.S.DB.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(db)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.DB.Close()
	q.S = reopened
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.RequestDigest != j.RequestDigest || got.State != "queued" || got.LockDigest != j.LockDigest {
		t.Fatal(got, e)
	}
	if e = q.Cancel("owner-a", j.ID); e != nil {
		t.Fatal(e)
	}
	if e = q.Cancel("owner-a", j.ID); e != nil {
		t.Fatal("cancel not idempotent", e)
	}
	got, e = q.Get("owner-a", j.ID)
	if e != nil || got.State != "cancelled" || !got.CancelRequested || got.Finished == "" {
		t.Fatal(got, e)
	}
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestRejectsRequestAndRepositoryIdentityChanges(t *testing.T) {
	q, in, _ := fixture(t)
	for _, change := range []func(*Input){func(i *Input) { i.Mode = "production_intrusive" }, func(i *Input) { i.Tools = []string{"sh"} }, func(i *Input) { i.Tools = []string{"bandit", "bandit"} }, func(i *Input) { i.Tools = []string{"syft", "bandit"} }, func(i *Input) { i.Duration = 121 }, func(i *Input) { i.Duration = 0 }, func(i *Input) { i.MapDigest = "bad" }} {
		bad := in
		change(&bad)
		if _, e := q.Enqueue("owner-a", "invalid-key-001", bad); !errors.Is(e, ErrInput) {
			t.Fatal(bad, e)
		}
	}
	if _, e := q.S.DB.Exec("UPDATE repositories SET map_digest=? WHERE id=?", domain.Hash([]byte("changed map")), in.Repository); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Enqueue("owner-a", "changed-key-001", in); !errors.Is(e, ErrConflict) {
		t.Fatal("stale repository map accepted", e)
	}
}
func TestToolLockChangeAndPayloadCorruption(t *testing.T) {
	q, in, _ := fixture(t)
	j, e := q.Enqueue("owner-a", "locked-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	q.LockDigest = domain.Hash([]byte("new reviewed lock"))
	if _, e = q.Enqueue("owner-a", "locked-key-001", in); !errors.Is(e, ErrConflict) {
		t.Fatal("idempotency switched tool pins", e)
	}
	if _, e = q.S.DB.Exec("UPDATE scanner_jobs SET payload=replace(payload,'120','119') WHERE id=?", j.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = q.Get("owner-a", j.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupted input accepted", e)
	}
	if e = q.Cancel("owner-a", j.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("corrupted input altered", e)
	}
}
func TestAuditFailureRollsBackEnqueueAndCancel(t *testing.T) {
	q, in, _ := fixture(t)
	trigger := func(on bool) {
		t.Helper()
		sql := "DROP TRIGGER refuse_scan_audit"
		if on {
			sql = "CREATE TRIGGER refuse_scan_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END"
		}
		if _, e := q.S.DB.Exec(sql); e != nil {
			t.Fatal(e)
		}
	}
	trigger(true)
	if _, e := q.Enqueue("owner-a", "atomic-key-001", in); e == nil {
		t.Fatal("enqueue without audit")
	}
	var n int
	q.S.DB.QueryRow("SELECT count(*) FROM scanner_jobs").Scan(&n)
	if n != 0 {
		t.Fatal("failed enqueue persisted", n)
	}
	trigger(false)
	j, e := q.Enqueue("owner-a", "atomic-key-001", in)
	if e != nil {
		t.Fatal(e)
	}
	trigger(true)
	if e = q.Cancel("owner-a", j.ID); e == nil {
		t.Fatal("cancel without audit")
	}
	got, e := q.Get("owner-a", j.ID)
	if e != nil || got.State != "queued" || got.CancelRequested {
		t.Fatal("failed cancellation persisted", got, e)
	}
	trigger(false)
	if e = q.S.VerifyAudit(); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentIdempotencyAndQueueBudget(t *testing.T) {
	q, in, _ := fixture(t)
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); j, e := q.Enqueue("owner-a", "concurrent-key", in); ids <- j.ID; errs <- e }()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if first != id {
			t.Fatal("duplicate concurrent jobs")
		}
	}
	for i := 0; i < 19; i++ {
		if _, e := q.Enqueue("owner-a", fmt.Sprintf("budget-key-%03d", i), in); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := q.Enqueue("owner-a", "budget-overflow", in); !errors.Is(e, ErrFull) {
		t.Fatal("unbounded active queue", e)
	}
	if e := q.Cancel("owner-a", first); e != nil {
		t.Fatal(e)
	}
	if _, e := q.Enqueue("owner-a", "budget-released", in); e != nil {
		t.Fatal(e)
	}
}

func TestRetainedQueueBudgetIncludesTerminalJobs(t *testing.T) {
	q, in, _ := fixture(t)
	j, e := q.Enqueue("owner-a", "retention-seed", in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.S.DB.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<999)
 INSERT INTO scanner_jobs(id,owner,repository,app,map_digest,lock_digest,request_digest,idempotency_key,payload,state,created_at,expires)
 SELECT 'retained-'||i,owner,repository,app,map_digest,lock_digest,request_digest,'retained-key-'||i,payload,'cancelled',created_at,expires FROM scanner_jobs CROSS JOIN n WHERE id=?`, j.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = q.Enqueue("owner-a", "retention-overflow", in); !errors.Is(e, ErrFull) {
		t.Fatal("terminal history escaped storage budget", e)
	}
}

func TestStoredOwnerAndRelationalIdentityMustMatchRequest(t *testing.T) {
	for _, column := range []string{"owner", "app"} {
		t.Run(column, func(t *testing.T) {
			q, in, _ := fixture(t)
			j, e := q.Enqueue("owner-a", "identity-key-001", in)
			if e != nil {
				t.Fatal(e)
			}
			value, owner := "app_other", "owner-a"
			if column == "owner" {
				value, owner = "owner-b", "owner-b"
			}
			if _, e = q.S.DB.Exec("UPDATE scanner_jobs SET "+column+"=? WHERE id=?", value, j.ID); e != nil {
				t.Fatal(e)
			}
			if _, e = q.Get(owner, j.ID); !errors.Is(e, ErrConflict) {
				t.Fatal("relational identity tampering accepted", column, e)
			}
		})
	}
}
