// SPDX-License-Identifier: Apache-2.0
// Package enginerelay forwards opaque TLS bytes from one private Unix listener
// to one fixed loopback TCP endpoint. It has no key, HTTP parser or engine API.
package enginerelay

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var ErrRelay = errors.New("private scanner engine relay unavailable")

func Endpoint(raw string) error {
	host, port, e := net.SplitHostPort(raw)
	n, ne := strconv.Atoi(port)
	if e != nil || host != "127.0.0.1" || ne != nil || n < 1024 || n > 65535 || strconv.Itoa(n) != port {
		return ErrRelay
	}
	return nil
}
func Serve(ctx context.Context, listener net.Listener, target string) error {
	if Endpoint(target) != nil {
		return ErrRelay
	}
	ctx, cancel := context.WithCancel(ctx)
	slots := make(chan struct{}, 8)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	for {
		local, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrRelay
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		workers.Go(func() {
			defer func() { <-slots }()
			defer local.Close()
			remote, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", target)
			if e != nil {
				return
			}
			defer remote.Close()
			// Bound idle or orphaned TLS streams independently from client HTTP limits.
			deadline := time.Now().Add(16 * time.Minute)
			local.SetDeadline(deadline)
			remote.SetDeadline(deadline)
			cancel := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
			defer cancel()
			done := make(chan struct{}, 1)
			go func() { io.Copy(remote, local); remote.Close(); done <- struct{}{} }()
			io.Copy(local, remote)
			local.Close()
			<-done
		})
	}
}
