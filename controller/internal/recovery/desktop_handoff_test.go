//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package recovery

import (
	"context"
	"path/filepath"
	"testing"

	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/store"
)

func TestRestoreRevokesDesktopHandoffsAndPreservesApprovedSnapshot(t *testing.T) {
	c, source, parent := fixture(t)
	seedAuthorities(t, source)
	const document = `{"schema_version":"1.0"}`
	for _, row := range []struct{ id, state string }{{"unused", "active"}, {"used", "delivered"}} {
		if _, err := source.DB.Exec("INSERT INTO desktop_handoffs(id,owner,connector,incident,document,digest,expires,state) VALUES(?,?,?,?,?,?,?,?)",
			row.id, "owner", "connector", "incident", document, domain.Hash([]byte(document)), 2147483647, row.state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := source.DB.Exec(`INSERT INTO desktop_analysis_drafts
 (id,owner,connector,incident,handoff,idempotency_key,document,content_digest,approved_bundle_digest,created_at,state)
 VALUES('retained-draft','owner','connector','incident','used','fixture-draft-key',?,?,?,1,'unverified')`,
		document, domain.Hash([]byte(document)), domain.Hash([]byte(document))); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.Exec(`INSERT INTO desktop_pairing_invites
  (id,owner,name,invite_hash,expires,minutes,allow_draft,state) VALUES('pending','owner','Workstation','fixture',2147483647,15,0,'approved');
  INSERT INTO desktop_paired_connectors VALUES('connector',0,'0123456789abcdef0123');`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DB.Exec(`INSERT INTO desktop_renewals(old_hash,connector,old_expires,approved_until,state)
 VALUES('connector-token-hash','connector',2147483647,2147483600,'approved')`); err != nil {
		t.Fatal(err)
	}
	bundle, receipt := makeBundle(t, c, parent)
	destination := filepath.Join(parent, "restored21")
	if _, err := Restore(context.Background(), c, bundle, destination, receipt.Bundle); err != nil {
		t.Fatal(err)
	}
	restored, err := store.OpenSnapshotSource(context.Background(), filepath.Join(destination, "data/aegis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	var count int
	if err = restored.DB.QueryRow("SELECT count(*) FROM desktop_handoffs WHERE connector='connector' AND state='revoked' AND document=? AND digest=?",
		document, domain.Hash([]byte(document))).Scan(&count); err != nil || count != 2 {
		t.Fatalf("restored handoff state: %d, %v", count, err)
	}
	if err = restored.DB.QueryRow("SELECT count(*) FROM desktop_analysis_drafts WHERE id='retained-draft' AND state='unverified' AND document=?", document).Scan(&count); err != nil || count != 1 {
		t.Fatalf("restored draft history: %d, %v", count, err)
	}
	if err = restored.DB.QueryRow("SELECT count(*) FROM desktop_pairing_invites").Scan(&count); err != nil || count != 0 {
		t.Fatalf("restored live invites: %d, %v", count, err)
	}
	if err = restored.DB.QueryRow(`SELECT count(*) FROM desktop_paired_connectors p JOIN connector_credentials c ON c.id=p.id
 WHERE p.id='connector' AND c.state='revoked'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("restored paired scope history: %d, %v", count, err)
	}
	if err = restored.DB.QueryRow("SELECT count(*) FROM desktop_renewals WHERE connector='connector' AND state='cancelled'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("restored renewal remained live: %d, %v", count, err)
	}
	if err = source.DB.QueryRow("SELECT count(*) FROM desktop_handoffs WHERE state IN ('active','delivered')").Scan(&count); err != nil || count != 2 {
		t.Fatalf("source handoff state: %d, %v", count, err)
	}
}
