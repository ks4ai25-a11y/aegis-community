// SPDX-License-Identifier: Apache-2.0
package main

import (
	"aegis.local/controller/internal/api"
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/ingest"
	"aegis.local/controller/internal/policy"
	"aegis.local/controller/internal/repository"
	"aegis.local/controller/internal/research"
	"aegis.local/controller/internal/store"
	"aegis.local/controller/internal/verify"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(domain.Version)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	root := env("AEGIS_DATA", "/var/lib/aegis")
	s, e := store.Open(filepath.Join(root, "aegis.db"))
	if e != nil {
		panic(e)
	}
	defer s.DB.Close()
	a := auth.New(s)
	if a.Bootstrap != "" {
		b, _ := json.Marshal(map[string]string{"event": "local_bootstrap_token", "token": a.Bootstrap, "expires_at": a.Expiry.UTC().Format(time.RFC3339)})
		fmt.Println(string(b))
	}
	m := &policy.Manager{S: s, Root: filepath.Join(root, "policies"), Binary: env("CADDY_BIN", "/usr/local/bin/caddy"), Socket: env("GATEWAY_SOCKET", "/run/gateway/admin.sock"), DeploySocket: env("DEPLOYER_SOCKET", "/run/deployer/deployer.sock"), Origin: "demo-origin:8080", Listen: ":8080", Log: env("GATEWAY_LOG", "/var/log/aegis/events.jsonl")}
	i := &ingest.Ingestor{S: s, Path: m.Log}
	go i.Run(ctx)
	go func() {
		for n := 0; n < 20; n++ {
			c, cn := context.WithTimeout(ctx, 3*time.Second)
			e := m.Reconcile(c)
			cn()
			if e == nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		m.Frozen.Store(true)
	}()
	q := &research.Queue{S: s}
	v := verify.Client{Socket: env("VERIFIER_SOCKET", "/run/verifier/verifier.sock")}
	worker := &research.Worker{Q: q, ID: "bundled-fixture-worker", Run: func(ctx context.Context, l research.Lease) (domain.Report, error) {
		return v.RunJob(ctx, l.Policy, l.Grant, l.Job.ID)
	}}
	go worker.Start(ctx)
	repos, e := repository.Open(s, os.Getenv("AEGIS_REPOSITORY_ROOT"))
	if e != nil {
		panic(e)
	}
	if repos.Root != nil {
		defer repos.Root.Close()
	}
	app := &api.Server{S: s, A: a, P: m, I: i, V: v, Q: q, R: repos, Assets: env("AEGIS_ASSETS", "/opt/aegis/console")}
	server := &http.Server{Addr: env("AEGIS_LISTEN", "127.0.0.1:7410"), Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	go func() {
		<-ctx.Done()
		c, cn := context.WithTimeout(context.Background(), 5*time.Second)
		defer cn()
		server.Shutdown(c)
	}()
	if e := server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		panic(e)
	}
}
