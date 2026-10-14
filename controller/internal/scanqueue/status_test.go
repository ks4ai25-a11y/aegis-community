// SPDX-License-Identifier: Apache-2.0
package scanqueue

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestStatusKeepsAdmissionSeparateFromTerminalState(t *testing.T) {
	q, in, _ := fixture(t)
	j, e := q.Enqueue("owner-a", "status-job-001", in)
	if e != nil {
		t.Fatal(e)
	}
	s, e := q.Status("owner-a", j.ID)
	if e != nil || s.Admission != "not_claimed" {
		t.Fatal(s, e)
	}
	if _, e = q.Status("owner-b", j.ID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("cross-owner status", e)
	}
	original := q.now()
	q.Now = func() time.Time { return original.Add(16 * time.Minute) }
	if e = q.Reconcile(); e != nil {
		t.Fatal(e)
	}
	s, e = q.Status("owner-a", j.ID)
	if e != nil || s.Job.State != "timeout" || s.Admission != "not_claimed" {
		t.Fatal("queue expiry invented cleanup state", s, e)
	}
	q.Now = func() time.Time { return original }
	l := enqueueClaim(t, q, in)
	s, e = q.Status("owner-a", l.Job.ID)
	if e != nil || s.Admission != "active" {
		t.Fatal(s, e)
	}
	if e = q.Fail(l, "SCANNER_EXECUTION_FAILED"); e != nil {
		t.Fatal(e)
	}
	s, e = q.Status("owner-a", l.Job.ID)
	if e != nil || s.Admission != "cleanup_required" {
		t.Fatal("terminal failure erased admission", s, e)
	}
	if _, e = q.S.DB.Exec("DELETE FROM scanner_dispatch"); e != nil {
		t.Fatal(e)
	}
	if _, e = q.Status("owner-a", l.Job.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("missing terminal admission became not_claimed", e)
	}
}
