// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import "database/sql"

// Status reads job and admission together. Terminal evidence never implies
// that a worker or its resources have stopped.
type Status struct {
	Job       Job    `json:"job"`
	Admission string `json:"execution_admission"`
}

func (q *Queue) Status(owner, id string) (Status, error) {
	tx, e := q.S.DB.Begin()
	if e != nil {
		return Status{}, e
	}
	defer tx.Rollback()
	j, e := read(tx.QueryRow("SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", id, owner))
	if e != nil {
		return Status{}, e
	}
	var admission string
	e = tx.QueryRow("SELECT state FROM scanner_dispatch WHERE job=?", id).Scan(&admission)
	if e == sql.ErrNoRows {
		// Missing dispatch is expected only for jobs that never ran.
		if j.State != "queued" && j.State != "cancelled" && !(j.State == "timeout" && j.Error == "QUEUE_EXPIRED") {
			return Status{}, ErrConflict
		}
		admission = "not_claimed"
		if j.State == "cancelled" {
			admission = "unconfirmed"
		}
	} else if e != nil {
		return Status{}, e
	} else if admission != "active" && admission != "cleanup_required" {
		return Status{}, ErrConflict
	}
	return Status{j, admission}, nil
}
