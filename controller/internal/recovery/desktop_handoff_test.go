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
		if _, err := source.DB.Exec("INSERT INTO desktop_handoffs VALUES(?,?,?,?,?,?,?,?)",
			row.id, "owner", "connector", "incident", document, domain.Hash([]byte(document)), 2147483647, row.state); err != nil {
			t.Fatal(err)
		}
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
	if err = source.DB.QueryRow("SELECT count(*) FROM desktop_handoffs WHERE state IN ('active','delivered')").Scan(&count); err != nil || count != 2 {
		t.Fatalf("source handoff state: %d, %v", count, err)
	}
}
