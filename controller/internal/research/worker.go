// SPDX-License-Identifier: Apache-2.0
package research

import (
	"aegis.local/controller/internal/domain"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

type Runner func(context.Context, Lease) (domain.Report, error)
type Worker struct {
	Q         *Queue
	Run       Runner
	ID        string
	LastError atomic.Value
}

func (w *Worker) Start(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l, e := w.Q.Claim(w.ID)
			if e == sql.ErrNoRows || errors.Is(e, ErrRejected) {
				continue
			}
			if e != nil {
				w.LastError.Store("queue claim failed")
				continue
			}
			w.execute(ctx, l)
		}
	}
}
func (w *Worker) execute(ctx context.Context, l Lease) {
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	guardExited := make(chan struct{})
	go func() {
		defer close(guardExited)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-jobCtx.Done():
				return
			case <-t.C:
				if w.Q.Guard(l) != nil {
					cancel()
					return
				}
			}
		}
	}()
	report, e := w.Run(jobCtx, l)
	close(done)
	<-guardExited
	code := ""
	var result *domain.Report
	if e == nil {
		result = &report
	} else if jobCtx.Err() == context.DeadlineExceeded {
		code = "JOB_DEADLINE_EXCEEDED"
	} else {
		code = "VERIFIER_UNAVAILABLE"
	}
	if e = w.Q.Finish(l, result, code); e != nil {
		w.LastError.Store(fmt.Sprintf("job persistence failed: %s", l.Job.ID))
	} else {
		w.LastError.Store("")
	}
}
