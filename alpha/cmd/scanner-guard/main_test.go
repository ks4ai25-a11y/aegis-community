// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/alpha/scanners"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAbsoluteDeadlineRejectsDelayedStartAndCapsRemainingBudget(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{-time.Second, 0} {
		if _, e := startupDeadline(now.Add(offset).Format(time.RFC3339Nano), 120, now); !errors.Is(e, errExpired) {
			t.Fatal("late container start accepted", e)
		}
	}
	soon := now.Add(1500 * time.Millisecond)
	got, e := startupDeadline(soon.Format(time.RFC3339Nano), 120, now)
	if e != nil || !got.Equal(soon) {
		t.Fatal("remaining job deadline replaced by fresh tool budget", got, e)
	}
	got, e = startupDeadline(now.Add(5*time.Minute).Format(time.RFC3339Nano), 2, now)
	if e != nil || !got.Equal(now.Add(2*time.Second)) {
		t.Fatal("absolute deadline widened fixed tool budget", got, e)
	}
}
func TestAbsoluteDeadlineRequiresCanonicalUTCAndFiniteWindow(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, raw := range []string{"", "forever", "2026-10-13T12:01:00+00:00", "2026-10-13T12:01:00.000Z", now.Add(16 * time.Minute).Format(time.RFC3339Nano), "2026-10-13T12:01:00Z;echo arbitrary"} {
		if _, e := startupDeadline(raw, 120, now); e == nil {
			t.Fatal("invalid deadline accepted", raw)
		}
	}
	for _, seconds := range []int{0, 121, -1} {
		if _, e := startupDeadline(now.Add(time.Minute).Format(time.RFC3339Nano), seconds, now); e == nil {
			t.Fatal("invalid tool duration accepted")
		}
	}
}

func TestGuardAcceptsOnlyFiniteOfflineToolPrograms(t *testing.T) {
	for _, tool := range []string{"semgrep_ce", "osv_v2", "trivy", "syft", "gitleaks", "bandit"} {
		binary, args, e := program(tool)
		if e != nil || binary == "" || len(args) == 0 {
			t.Fatal(tool, e)
		}
	}
	for _, tool := range []string{"sh", "curl", "/src/script.sh", "semgrep_ce;curl remote"} {
		if _, _, e := program(tool); e == nil {
			t.Fatal("arbitrary program accepted", tool)
		}
	}
}

func TestContainerStreamBudgetCancelsBeforeForwardingOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &bytes.Buffer{}
	stream := &boundedStream{writer: output, used: scanners.MaxOutput, cancel: cancel}
	if _, e := stream.Write([]byte("must not be forwarded")); e == nil {
		t.Fatal("overflow accepted")
	}
	if ctx.Err() == nil || output.Len() != 0 {
		t.Fatal("container stream budget did not stop forwarding")
	}
}

func TestGuardUsesDatabaseInvocationOnlyWhenMounted(t *testing.T) {
	_, plain, _ := programWith("trivy", func(string) bool { return false })
	_, withDB, _ := programWith("trivy", func(string) bool { return true })
	if strings.Contains(strings.Join(plain, " "), "/db/trivy") || !strings.Contains(strings.Join(withDB, " "), "--cache-dir /db/trivy") {
		t.Fatal(plain, withDB)
	}
	if _, args, e := programWith("bandit", func(string) bool { return true }); e != nil || strings.Contains(strings.Join(args, " "), "/db") {
		t.Fatal("non-advisory tool changed by a database mount", args, e)
	}
}
