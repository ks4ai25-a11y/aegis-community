// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"context"
	"errors"
	"time"
)

var ErrAuthority = errors.New("scanner execution authority withdrawn")
var ErrTask = errors.New("scanner worker task failed")

// RunWithLease bounds a cooperative worker task by the original deadline and
// renews its controller lease every five seconds. It joins the renewal loop and
// waits for the task to return, including its cleanup, before returning itself.
// The task must honor cancellation and use a bounded, independently stoppable
// executor: a Go context does not forcibly stop untrusted code. A nil return only
// reports local task/authority checks; it does not ingest a receipt, complete a
// job, assert tool success, or release cleanup admission.
func (c *Client) RunWithLease(ctx context.Context, l Lease, task func(context.Context) error) error {
	return c.runWithLease(ctx, l, task, 5*time.Second)
}
func (c *Client) runWithLease(ctx context.Context, l Lease, task func(context.Context) error, interval time.Duration) error {
	if task == nil || interval <= 0 || interval >= 15*time.Second {
		return ErrTask
	}
	if c.validate(l) != nil {
		return ErrAuthority
	}
	run, cancel := context.WithDeadline(ctx, l.Deadline)
	defer cancel()
	if c.Guard(run, l) != nil {
		return ErrAuthority
	}
	// Cancellation of a renewal request on normal task completion is separate
	// from cancellation of task authority. It must not look like a failed lease.
	heartbeat, stop := context.WithCancel(run)
	joined := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeat.Done():
				joined <- nil
				return
			case <-ticker.C:
				if c.Guard(heartbeat, l) != nil {
					if heartbeat.Err() != nil {
						joined <- nil
						return
					}
					cancel()
					joined <- ErrAuthority
					return
				}
			}
		}
	}()
	// Deliberately synchronous: do not abandon a task goroutine and falsely
	// report that its workspace/processes have stopped after lease withdrawal.
	taskErr := task(run)
	stop()
	guardErr := <-joined
	if guardErr != nil {
		return guardErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if run.Err() != nil {
		return run.Err()
	}
	if taskErr != nil {
		return ErrTask
	}
	// Confirm authority after cleanup too; no receipt submission should assume
	// that a prior renewal was still live throughout the final task interval.
	if c.Guard(run, l) != nil {
		return ErrAuthority
	}
	return nil
}
