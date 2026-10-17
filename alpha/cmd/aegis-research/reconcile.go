// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/alpha/engineobserve"
	"aegis.local/alpha/executor"
	"aegis.local/alpha/reconcile"
	"aegis.local/alpha/workerchannel"
	"aegis.local/alpha/workspace"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// reconcileConfig is a private, operator-written file. It names the
// reconciler's own enrollment and the observer's own engine identity; it never
// carries worker leases, authorizer credentials or broker keys.
type reconcileConfig struct {
	Socket            string `json:"controller_socket"`
	Credential        string `json:"reconciler_credential_file"`
	Owner             string `json:"owner_id"`
	Reconciler        string `json:"reconciler_id"`
	Binding           string `json:"binding_digest"`
	Engine            string `json:"engine_digest"`
	Registry          string `json:"registry_digest"`
	Policy            string `json:"policy_digest"`
	Namespace         string `json:"registry_namespace_digest"`
	SourceRoot        string `json:"canonical_aegis_source_root"`
	WorkspaceRegistry string `json:"canonical_workspace_registry"`
	ObserverEndpoint  string `json:"observer_endpoint"`
	ObserverIdentity  string `json:"observer_identity_directory"`
	BrokerCertificate string `json:"broker_certificate_file"`
}

func reconcileCleanup(configPath, job, generation string) error {
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return fmt.Errorf("private reconcile configuration required")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("private reconcile configuration required")
	}
	var c reconcileConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return fmt.Errorf("invalid reconcile configuration")
	}
	root, err := filepath.EvalSymlinks(c.SourceRoot)
	if err != nil || root != c.SourceRoot || !filepath.IsAbs(root) {
		return fmt.Errorf("canonical source root required")
	}
	lock, err := executor.ConfiguredToolLockDigest(filepath.Join(root, "tools/scanners.lock.json"))
	if err != nil {
		return fmt.Errorf("trusted tool lock unavailable")
	}
	certificate, err := os.ReadFile(c.BrokerCertificate)
	if err != nil || len(certificate) > 16<<10 {
		return fmt.Errorf("broker certificate unavailable")
	}
	client, err := workerchannel.NewReconciler(c.Socket, c.Credential, c.Owner, c.Reconciler, c.Binding, c.Engine, c.Registry, c.Policy, c.Namespace, lock)
	if err != nil {
		return fmt.Errorf("private reconciler configuration unavailable")
	}
	defer client.Close()
	observer, err := engineobserve.Open(engineobserve.Config{Endpoint: c.ObserverEndpoint, IdentityDirectory: c.ObserverIdentity, ExpectedEngine: c.Engine, BrokerCertificatePEM: certificate})
	if err != nil {
		return fmt.Errorf("independent engine observer unavailable")
	}
	defer observer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := reconcile.Release{Controller: client, Observer: observer, Barrier: workspace.WithBoundEmptyRegistry, Registry: c.WorkspaceRegistry, Namespace: c.Namespace}.Run(ctx, job, generation)
	if err != nil {
		return fmt.Errorf("scanner cleanup not released")
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
