// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"io"
	"net"
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
