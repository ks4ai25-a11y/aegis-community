// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/controller/internal/verify"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessDoesNotSendApplicationRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 1)
		n, err := conn.Read(b)
		if n != 0 || !errors.Is(err, io.EOF) {
			result <- errors.New("readiness sent application bytes or did not close")
			return
		}
		result <- nil
	}()
	if err := waitForListener(context.Background(), listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestReadinessHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForListener(ctx, "127.0.0.1:1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestFixtureDrainWaitsPastUnrelatedRuleForExpectedCorrelatedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	initial := []byte("{\"request_id\":\"negative\",\"rule_id\":\"920350\"}\n")
	if e := os.WriteFile(path, initial, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if e != nil {
			done <- e
			return
		}
		_, e = f.WriteString("{\"request_id\":\"other-request\",\"rule_id\":\"942100\"}\n{\"request_id\":\"negative\",\"rule_id\":\"942100\"}\n")
		f.Close()
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rules, e := waitForFixtureRules(ctx, path, "negative")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e != nil || len(rules) != 2 || rules[0] != "920350" || rules[1] != "942100" {
		t.Fatal("unrelated first rule ended evidence collection", rules, e)
	}
}
func TestFixtureDrainRefusesUncorrelatedOrMissingExpectedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if e := os.WriteFile(path, []byte("{\"request_id\":\"other\",\"rule_id\":\"942100\"}\n{\"request_id\":\"negative\",\"rule_id\":\"920350\"}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	rules, e := waitForFixtureRules(context.Background(), path, "negative")
	if e != nil || len(rules) != 1 || rules[0] != "920350" || verify.Classify(200, 403, rules, "protect") != "FAIL" {
		t.Fatal("wrong request supplied expected evidence", rules, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := waitForFixtureRules(ctx, path, "negative"); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled drain ignored", e)
	}
}
