// SPDX-License-Identifier: BUSL-1.1
package scanqueue

import (
	"aegis.local/controller/internal/scannerauth"
	"aegis.local/source/scanevidence"
	"context"
	"database/sql"
	"regexp"
	"time"
)

var challengePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// LiveLaunch is read-only: no lease renewal, mutation ticket, admission change
// or secret lease token is produced. The same transaction verifies all scope.
func (q *Queue) LiveLaunch(ctx context.Context, v scanevidence.VerifierIdentity, name, challenge string) (scanevidence.LiveLaunchRecord, error) {
	if !containerID.MatchString(name) || !challengePattern.MatchString(challenge) {
		return scanevidence.LiveLaunchRecord{}, ErrInput
	}
	tx, e := q.S.DB.BeginTx(ctx, nil)
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	defer tx.Rollback()
	if e = scannerauth.AuthorizeVerifierTx(tx, v, q.now().Unix()); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT l.job FROM scanner_launches l JOIN scanner_jobs j ON j.id=l.job WHERE j.owner=? AND l.container=? LIMIT 2", v.Owner, name)
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return scanevidence.LiveLaunchRecord{}, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	if len(ids) == 0 {
		return scanevidence.LiveLaunchRecord{}, sql.ErrNoRows
	}
	if len(ids) != 1 {
		return scanevidence.LiveLaunchRecord{}, ErrConflict
	}
	// Generation-enabled dispatches require durable admission. The old
	// observation-only serving mode must never stand in for that protocol.
	var generations int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM scanner_allocation_generations WHERE job=?", ids[0]).Scan(&generations); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	if generations != 0 {
		return scanevidence.LiveLaunchRecord{}, ErrLease
	}
	record, e := q.cleanupContextTx(ctx, tx, v, ids[0])
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	base, e := q.engineBindingTx(tx, v.Owner)
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, ErrContextUnbound
	}
	journal, e := q.journalBindingTx(tx, v.Owner, base)
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, ErrContextUnbound
	}
	broker, e := q.brokerBindingTx(tx, v.Owner)
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, ErrContextUnbound
	}
	d := scanevidence.LiveLaunchContext{Schema: "1.0", Challenge: challenge, Container: name, Context: record, EngineBinding: base, JournalBinding: journal, BrokerBinding: broker, Live: true, MetadataOnly: true}
	out, e := scanevidence.NewLiveLaunch(d)
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, ErrLease
	}
	c := record.Document
	// Match current grant/map/lock, configured guard set, live worker enrollment
	// and selected broker without reading or disclosing the dispatch token hash.
	j, e := read(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM scanner_jobs WHERE id=? AND owner=?", c.Job, v.Owner))
	if e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	if !q.Guards.Valid() || q.Guards.Digest != c.GuardSet {
		return scanevidence.LiveLaunchRecord{}, ErrLease
	}
	if _, e = q.authority(tx, j); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	if e = workerAuthority(tx, c.Worker, v.Owner, q.now().Unix()); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	if e = q.matchBrokerTx(tx, c.Worker, v.Owner); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	lease, le := time.Parse(time.RFC3339, c.LeaseUntil)
	deadline, de := time.Parse(time.RFC3339, c.Deadline)
	if le != nil || de != nil || !lease.After(q.now()) || !deadline.After(q.now()) {
		return scanevidence.LiveLaunchRecord{}, ErrLease
	}
	if e = ctx.Err(); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	if e = scannerauth.AuthorizeVerifierTx(tx, v, q.now().Unix()); e != nil {
		return scanevidence.LiveLaunchRecord{}, e
	}
	return out, nil
}
