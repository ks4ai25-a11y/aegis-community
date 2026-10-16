// SPDX-License-Identifier: Apache-2.0
package enginerelay

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFixedLoopbackTarget(t *testing.T) {
	for _, target := range []string{"localhost:2376", "0.0.0.0:2376", "[::1]:2376", "127.0.0.1:443", "127.0.0.1:02376", "127.0.0.1:65536", "tcp://127.0.0.1:2376", "127.0.0.1:2376?x=1"} {
		if Endpoint(target) == nil {
			t.Fatal("unrestricted endpoint", target)
		}
	}
	if Endpoint("127.0.0.1:2376") != nil {
		t.Fatal("loopback refused")
	}
}
func TestOpaqueDuplexForwardingAndCancellationJoin(t *testing.T) {
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	short, e := os.MkdirTemp("", "aegis-relay-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(short)
	path := filepath.Join(short, "relay.sock")
	listener, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, target.Addr().String()) }()
	local, e := net.Dial("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	defer local.Close()
	remote, e := target.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer remote.Close()
	payload := []byte{0, 1, 2, 255, 128}
	local.Write(payload)
	actual := make([]byte, len(payload))
	remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = io.ReadFull(remote, actual); e != nil || string(actual) != string(payload) {
		t.Fatal("bytes changed")
	}
	remote.Write(payload)
	local.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = io.ReadFull(local, actual); e != nil || string(actual) != string(payload) {
		t.Fatal("reverse bytes changed")
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay cancellation did not join")
	}
}
