// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/store"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type changeRig struct {
	q     *Queue
	reg   *repository.Registry
	dir   string
	repo  string
	clock time.Time
}

func newChangeRig(t *testing.T) *changeRig {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	s.DB.Exec("INSERT INTO owners VALUES('owner-a','test',?),('owner-b','test',?)", domain.Now(), domain.Now())
	s.DB.Exec("INSERT INTO settings VALUES('repository_mount_owner','owner-a')")
	root, _ := filepath.EvalSymlinks(t.TempDir())
	dir := filepath.Join(root, "fixture")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("print('v1')\n"), 0600)
	reg, e := repository.Open(s, root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { reg.Root.Close() })
	rec, e := reg.Connect("owner-a", "app_demo", "fixture", true)
	if e != nil {
		t.Fatal(e)
	}
	r := &changeRig{reg: reg, dir: dir, repo: rec.ID, clock: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)}
	r.q = &Queue{S: s, LockDigest: domain.Hash([]byte("trusted-tool-lock")), Now: func() time.Time { return r.clock }}
	return r
}

func (r *changeRig) refresh(ctx context.Context, owner, repo string) (string, error) {
	rec, e := r.reg.Get(owner, repo)
	if e != nil {
		return "", e
	}
	out, e := r.reg.ConnectContext(ctx, owner, rec.App, rec.Asset, true)
	return out.MapDigest, e
}

func (r *changeRig) check(t *testing.T) string {
	t.Helper()
	r.clock = r.clock.Add(10 * time.Minute)
	out, e := r.q.CheckChanges(context.Background(), r.refresh, 10, 5*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if len(out) != 1 {
		t.Fatalf("outcomes %v", out)
	}
	return out[0].Outcome
}

func (r *changeRig) jobs(t *testing.T) []Job {
	t.Helper()
	j, e := r.q.List("owner-a")
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestChangeTriggeredRescan(t *testing.T) {
	r := newChangeRig(t)
	ctx := context.Background()
	if out, _ := r.q.CheckChanges(ctx, r.refresh, 10, 0); len(out) != 0 {
		t.Fatal("repository without opt-in was checked", out)
	}
	if _, e := r.q.SetRescanPolicy("owner-b", r.repo, true, []string{"bandit"}, 60); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("another owner set a policy", e)
	}
	for _, tools := range [][]string{{}, {"shell"}, {"bandit", "bandit"}} {
		if _, e := r.q.SetRescanPolicy("owner-a", r.repo, true, tools, 60); !errors.Is(e, ErrPolicy) {
			t.Fatal("invalid tools accepted", tools, e)
		}
	}
	p, e := r.q.SetRescanPolicy("owner-a", r.repo, true, []string{"semgrep_ce", "bandit"}, 60)
	if e != nil || !p.Enabled || p.Tools[0] != "bandit" || !digestPattern.MatchString(p.BaselineDigest) {
		t.Fatal(p, e)
	}
	if o := r.check(t); o != "unchanged" || len(r.jobs(t)) != 0 {
		t.Fatal("unchanged repository scanned", o)
	}
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('v2')\n"), 0600)
	if o := r.check(t); o != "enqueued" {
		t.Fatal(o)
	}
	jobs := r.jobs(t)
	current, _ := r.reg.Get("owner-a", r.repo)
	if len(jobs) != 1 || jobs[0].Input.MapDigest != current.MapDigest || jobs[0].Input.Tools[1] != "semgrep_ce" || jobs[0].Input.Duration != 60 || jobs[0].State != "queued" {
		t.Fatal(jobs)
	}
	if o := r.check(t); o != "unchanged" || len(r.jobs(t)) != 1 {
		t.Fatal("same digest scanned twice", o)
	}
	// A further change while that job is queued waits for it.
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('v3')\n"), 0600)
	if o := r.check(t); o != "deferred_active_job" {
		t.Fatal(o)
	}
	if e := r.q.Cancel("owner-a", jobs[0].ID); e != nil {
		t.Fatal(e)
	}
	if o := r.check(t); o != "enqueued" || len(r.jobs(t)) != 2 {
		t.Fatal(o)
	}
	// Checks respect the minimum interval.
	if out, _ := r.q.CheckChanges(ctx, r.refresh, 10, time.Hour); len(out) != 0 {
		t.Fatal("checked again within the interval", out)
	}
	// Disabling stops further scans but does not cancel queued work.
	if p, e = r.q.SetRescanPolicy("owner-a", r.repo, false, nil, 0); e != nil || p.Enabled {
		t.Fatal(p, e)
	}
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('v4')\n"), 0600)
	r.clock = r.clock.Add(time.Hour)
	if out, _ := r.q.CheckChanges(ctx, r.refresh, 10, 0); len(out) != 0 || len(r.jobs(t)) != 2 {
		t.Fatal("disabled policy scanned", out)
	}
}

func TestRescanIsIdempotentAcrossLostBaseline(t *testing.T) {
	r := newChangeRig(t)
	p, _ := r.q.SetRescanPolicy("owner-a", r.repo, true, []string{"bandit"}, 30)
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('v2')\n"), 0600)
	if o := r.check(t); o != "enqueued" {
		t.Fatal(o)
	}
	first := r.jobs(t)[0]
	r.q.Cancel("owner-a", first.ID)
	// Simulate a crash before the baseline was saved: the old baseline returns.
	cur, _ := r.q.loadPolicy("owner-a", r.repo)
	cur.BaselineDigest = p.BaselineDigest
	r.q.savePolicy(cur)
	if o := r.check(t); o != "enqueued" || len(r.jobs(t)) != 1 {
		t.Fatal("restart created a duplicate job", o, len(r.jobs(t)))
	}
}

func TestRescanDefersWhileCleanupHeld(t *testing.T) {
	r := newChangeRig(t)
	r.q.SetRescanPolicy("owner-a", r.repo, true, []string{"bandit"}, 30)
	// The held cleanup belongs to another of the owner's repositories.
	other := filepath.Join(filepath.Dir(r.dir), "other")
	os.Mkdir(other, 0700)
	os.WriteFile(filepath.Join(other, "x.py"), []byte("x\n"), 0600)
	rec, e := r.reg.Connect("owner-a", "app_demo", "other", true)
	if e != nil {
		t.Fatal(e)
	}
	j, e := r.q.Enqueue("owner-a", "held-cleanup-job", Input{"1.0", "app_demo", rec.ID, rec.MapDigest, "repo_offline", []string{"bandit"}, 30})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.q.S.DB.Exec("INSERT INTO scanner_workers VALUES('w','owner-a',?,'active',?,?)", domain.Hash([]byte("w")), r.clock.Add(time.Hour).Unix(), domain.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = r.q.S.DB.Exec("INSERT INTO scanner_dispatch(slot,job,worker,token_hash,lease_until,deadline,state) VALUES(1,?,'w',?,0,0,'cleanup_required')", j.ID, domain.Hash([]byte("t"))); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('v2')\n"), 0600)
	if o := r.check(t); o != "deferred_cleanup_held" {
		t.Fatal(o)
	}
}

func TestRescanRetriesOnceAfterToolFailure(t *testing.T) {
	r := newChangeRig(t)
	r.q.SetRescanPolicy("owner-a", r.repo, true, []string{"bandit"}, 30)
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('v2')\n"), 0600)
	if o := r.check(t); o != "enqueued" {
		t.Fatal(o)
	}
	first := r.jobs(t)[0]
	if _, e := r.q.S.DB.Exec("UPDATE scanner_jobs SET state='tool_error' WHERE id=?", first.ID); e != nil {
		t.Fatal(e)
	}
	if o := r.check(t); o != "retried_after_failure" || len(r.jobs(t)) != 2 {
		t.Fatal(o, len(r.jobs(t)))
	}
	second := r.jobs(t)[0]
	r.q.S.DB.Exec("UPDATE scanner_jobs SET state='tool_error' WHERE id=?", second.ID)
	if o := r.check(t); o != "unchanged" || len(r.jobs(t)) != 2 {
		t.Fatal("retried more than once", o)
	}
}

func TestMapPruningKeepsMapsReferencedByJobs(t *testing.T) {
	r := newChangeRig(t)
	r.q.SetRescanPolicy("owner-a", r.repo, true, []string{"bandit"}, 30)
	os.WriteFile(filepath.Join(r.dir, "app.py"), []byte("print('scanned')\n"), 0600)
	if o := r.check(t); o != "enqueued" {
		t.Fatal(o)
	}
	scanned := r.jobs(t)[0].Input.MapDigest
	for i := 0; i < 105; i++ {
		os.WriteFile(filepath.Join(r.dir, "app.py"), []byte(fmt.Sprintf("print(%d)\n", i)), 0600)
		if _, e := r.reg.Refresh(context.Background(), "owner-a", r.repo); e != nil {
			t.Fatal("change", i, e)
		}
	}
	var kept, total int
	r.q.S.DB.QueryRow("SELECT count(*) FROM application_maps WHERE repository=? AND digest=?", r.repo, scanned).Scan(&kept)
	r.q.S.DB.QueryRow("SELECT count(*) FROM application_maps WHERE repository=?", r.repo).Scan(&total)
	if kept != 1 || total > 100 {
		t.Fatal("referenced map pruned or history unbounded", kept, total)
	}
}
