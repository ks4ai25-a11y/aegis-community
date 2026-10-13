package main

import (
	"aegis.local/alpha/scanners"
	"bytes"
	"context"
	"testing"
)

func TestGuardAcceptsOnlyFiniteOfflineToolPrograms(t *testing.T) {
	for _, tool := range []string{"semgrep_ce", "osv_v2", "trivy", "syft", "gitleaks"} {
		binary, args, e := program(tool)
		if e != nil || binary == "" || len(args) == 0 {
			t.Fatal(tool, e)
		}
	}
	for _, tool := range []string{"sh", "curl", "/src/script.sh", "bandit", "semgrep_ce;curl remote"} {
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
