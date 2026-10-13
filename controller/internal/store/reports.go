// SPDX-License-Identifier: Apache-2.0
package store

import (
	"aegis.local/controller/internal/domain"
	"encoding/json"
	"fmt"
)

func (s *Store) SaveReport(owner string, r domain.Report) error {
	digest := r.Digest
	r.Digest = ""
	if digest != domain.Digest(r) {
		return fmt.Errorf("report digest mismatch")
	}
	r.Digest = digest
	b, e := json.Marshal(r)
	if e != nil || len(b) > 65536 {
		return fmt.Errorf("report size invalid")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT OR IGNORE INTO reports VALUES(?,?)", digest, string(b)); e == nil {
		_, e = tx.Exec("INSERT OR IGNORE INTO report_owners VALUES(?,?)", digest, owner)
	}
	if e == nil {
		e = tx.Commit()
	}
	return e
}
