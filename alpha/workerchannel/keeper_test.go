//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package workerchannel

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestKeeperWithdrawsAndJoinsTask(t *testing.T) {
	var guards atomic.Int32
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guards.Add(1) > 1 {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte(`{"state":"running"}`))
	}))
	stopped := false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e := c.runWithLease(ctx, claim(), func(run context.Context) error { <-run.Done(); stopped = true; return nil }, 10*time.Millisecond)
	if !errors.Is(e, ErrAuthority) || !stopped {
		t.Fatal("lease refusal did not cancel and join task")
	}
	before := guards.Load()
	time.Sleep(25 * time.Millisecond)
	if guards.Load() != before {
		t.Fatal("renewal leaked beyond return")
	}
}
func TestKeeperRefusesBeforeTaskAndRedactsTaskError(t *testing.T) {
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	ran := false
	if e := c.RunWithLease(context.Background(), claim(), func(context.Context) error { ran = true; return nil }); !errors.Is(e, ErrAuthority) || ran {
		t.Fatal("task ran without live authority")
	}
	c, _ = fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"state":"running"}`)) }))
	if e := c.RunWithLease(context.Background(), claim(), func(context.Context) error { return errors.New("private source details") }); !errors.Is(e, ErrTask) {
		t.Fatal("task error was not redacted")
	}
}
func TestKeeperFinalGuardAndParentCancellation(t *testing.T) {
	var guards atomic.Int32
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guards.Add(1) > 1 {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte(`{"state":"running"}`))
	}))
	if e := c.RunWithLease(context.Background(), claim(), func(context.Context) error { return nil }); !errors.Is(e, ErrAuthority) {
		t.Fatal("final authority refusal ignored")
	}
	c, _ = fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"state":"running"}`)) }))
	ctx, cancel := context.WithCancel(context.Background())
	if e := c.RunWithLease(ctx, claim(), func(run context.Context) error { cancel(); <-run.Done(); return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal("parent cancellation ignored")
	}
}
func TestKeeperDeadlineDoesNotReportSuccess(t *testing.T) {
	c, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"state":"running"}`)) }))
	l := claim()
	l.Deadline = time.Now().Add(35 * time.Millisecond)
	if e := c.runWithLease(context.Background(), l, func(run context.Context) error { <-run.Done(); return nil }, 10*time.Millisecond); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("deadline falsely succeeded")
	}
}
