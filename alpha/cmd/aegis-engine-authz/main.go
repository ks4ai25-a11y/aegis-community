// SPDX-License-Identifier: Apache-2.0
// An opt-in experimental plugin for a separately provisioned scanner daemon.
package main

import (
	"aegis.local/alpha/engineauthz"
	"aegis.local/alpha/enginejournal"
	"aegis.local/source"
	"aegis.local/source/privateipc"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func run() error {
	if len(os.Args) == 4 && os.Args[1] == "init" {
		_, e := enginejournal.InitializeEmpty(os.Args[2], os.Args[3])
		return e
	}
	// Paths and digests are operator configuration, never caller-selected RPC data.
	if !(len(os.Args) == 9 && os.Args[1] == "serve" || len(os.Args) == 15 && os.Args[1] == "serve-bound" || len(os.Args) == 16 && (os.Args[1] == "serve-admitted" || os.Args[1] == "admitted-policy-input")) {
		return fmt.Errorf("usage: aegis-engine-authz init JOURNAL ENGINE_DIGEST | serve SOCKET JOURNAL ENGINE_DIGEST WORK_ROOT UID GID TOOL_LOCK | serve-bound SOCKET JOURNAL ENGINE_DIGEST WORK_ROOT UID GID TOOL_LOCK CONTROLLER_SOCKET OBSERVER_CREDENTIAL OWNER VERIFIER_ID REGISTRY_DIGEST RULES_DIGEST_OR_DASH | serve-admitted|admitted-policy-input SOCKET JOURNAL ENGINE_DIGEST WORK_ROOT UID GID TOOL_LOCK CONTROLLER_SOCKET AUTHORIZER_CREDENTIAL OWNER AUTHORIZER_ID REGISTRY_DIGEST REGISTRY_NAMESPACE_DIGEST RULES_DIGEST_OR_DASH")
	}
	uid, e := strconv.Atoi(os.Args[6])
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(os.Args[7])
	if e != nil {
		return e
	}
	images, b, e := engineauthz.ReadLock(os.Args[8])
	if e != nil {
		return e
	}

	cfg := engineauthz.Config{WorkRoot: os.Args[5], JournalRoot: os.Args[3], EngineDigest: os.Args[4], UID: uid, GID: gid, Images: images}
	if os.Args[1] == "serve-bound" {
		rules := os.Args[14]
		if rules == "-" {
			rules = ""
		}
		cfg.Live = &engineauthz.LiveConfig{Socket: os.Args[9], Credential: os.Args[10], Owner: os.Args[11], Verifier: os.Args[12], Registry: os.Args[13], LockPath: os.Args[8], RulesDigest: rules}
	}
	if os.Args[1] == "serve-admitted" || os.Args[1] == "admitted-policy-input" {
		rules := os.Args[15]
		if rules == "-" {
			rules = ""
		}
		cfg.Admitted = &engineauthz.AdmittedConfig{Socket: os.Args[9], Credential: os.Args[10], Owner: os.Args[11], Authorizer: os.Args[12], Registry: os.Args[13], Namespace: os.Args[14], LockPath: os.Args[8], RulesDigest: rules}
		if os.Args[1] == "admitted-policy-input" {
			digest, e := engineauthz.AdmittedPolicyDigest(cfg, *cfg.Admitted)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": "1.0", "policy_digest": digest, "controller_binding_verified": false, "engine_write_authorized": false, "cleanup_release_authorized": false})
		}
	}
	policy, e := engineauthz.Open(cfg)
	if e != nil {
		return e
	}
	defer policy.Close()
	listener, e := privateipc.Listen(os.Args[2])
	if e != nil {
		return e
	}
	defer listener.Close()
	// Public source identity only. No certificate, source or credential bytes.
	fmt.Fprintf(os.Stderr, "scanner engine authorization ready; tool_lock_digest=%s; cleanup_release_authorized=false\n", source.Hash(b))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return policy.Serve(ctx, listener)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "scanner engine authorization unavailable")
		os.Exit(1)
	}
}
