// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/domain"
	"aegis.local/source"
	"errors"
	"testing"
	"time"
)

func TestDatabaseApprovalIsBoundIntoTheJob(t *testing.T) {
	q, in, _ := fixture(t)
	in.Tools = []string{"bandit", "osv_v2", "trivy"}
	digest := domain.Hash([]byte("osv-db"))
	now := q.now()
	if _, e := q.ApproveDatabase("operator", "bandit", digest, now.Format(time.RFC3339)); !errors.Is(e, ErrDatabase) {
		t.Fatal("non-advisory tool approved")
	}
	if _, e := q.ApproveDatabase("operator", "osv_v2", digest, now.Add(-24*time.Hour).Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	// A stale approval (built long ago) is not attached.
	if _, e := q.ApproveDatabase("operator", "trivy", domain.Hash([]byte("old")), now.Add(-30*24*time.Hour).Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	j, e := q.Enqueue("owner-a", "with-approved-db", in)
	if e != nil {
		t.Fatal(e)
	}
	if j.Input.Databases["osv_v2"] != digest || j.Input.Databases["trivy"] != "" {
		t.Fatal("approvals not bound", j.Input.Databases)
	}
	again, _ := q.Get("owner-a", j.ID)
	if again.Input.Databases["osv_v2"] != digest || again.RequestDigest != j.RequestDigest {
		t.Fatal("binding not durable")
	}
	// Receipt validation uses the job's own binding.
	x, e := expectedReceipt(j, source.Map{}, Pin{"2.0", domain.Hash([]byte("img"))}, "osv_v2", now)
	if e != nil || x.Database != digest {
		t.Fatal("expected receipt does not carry the approved digest", x.Database, e)
	}
	// Revoking later does not change an existing job; an exact retry returns it.
	q.RevokeDatabase("operator", "osv_v2")
	if r, e := q.Enqueue("owner-a", "with-approved-db", Input{in.Schema, in.App, in.Repository, in.MapDigest, in.Mode, in.Tools, in.Duration, nil}); e != nil || r.ID != j.ID {
		t.Fatal("exact retry after revocation", e)
	}
	// Requesters cannot choose a database.
	bad := in
	bad.Databases = map[string]string{"osv_v2": digest}
	if _, e := q.Enqueue("owner-a", "self-approved", bad); !errors.Is(e, ErrInput) {
		t.Fatal("requester-chosen database accepted")
	}
	var audits int
	q.S.DB.QueryRow("SELECT count(*) FROM audit WHERE json_extract(document,'$.action') IN ('scanner.database_approved','scanner.database_revoked')").Scan(&audits)
	if audits != 3 {
		t.Fatal("approvals not audited", audits)
	}
}
