// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"aegis.local/alpha/enginejournal"
	"aegis.local/alpha/engineobserve"
	"aegis.local/alpha/executor"
	"aegis.local/alpha/reconcile"
	"aegis.local/alpha/workerchannel"
	"aegis.local/alpha/workspace"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// reconcileRepair resolves the pending intents of one closed generation from
// sealed quarantine evidence (ADR 057). It never releases a slot.
func reconcileRepair(configPath, job, generation string) error {
	c, lock, certificate, err := loadReconcile(configPath)
	if err != nil {
		return err
	}
	journal, err := filepath.EvalSymlinks(c.AuthorizerJournal)
	if c.AuthorizerJournal == "" || err != nil || journal != c.AuthorizerJournal || !filepath.IsAbs(journal) {
		return fmt.Errorf("canonical sealed authorizer journal required")
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
	read := func(attempt string) (enginejournal.Evidence, error) {
		return enginejournal.ReadEvidence(journal, c.Engine, attempt)
	}
	out, err := reconcile.Repair{Controller: client, Observer: observer, Journal: read, Namespace: c.Namespace}.Run(ctx, job, generation)
	if errors.Is(err, reconcile.ErrRemovalOutstanding) {
		return fmt.Errorf("scanner removal outstanding: resume it through the quarantined plugin, then repair again")
	}
	if err != nil {
		return fmt.Errorf("scanner mutation repair refused; quarantine retained")
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// recoverObserved removes preserved workspaces of the configured registry
// whose exact bound container the independent observer reports absent on the
// original engine. It is the TLS-path counterpart of recover-workspaces.
func recoverObserved(configPath string) error {
	c, _, certificate, err := loadReconcile(configPath)
	if err != nil {
		return err
	}
	observer, err := engineobserve.Open(engineobserve.Config{Endpoint: c.ObserverEndpoint, IdentityDirectory: c.ObserverIdentity, ExpectedEngine: c.Engine, BrokerCertificatePEM: certificate})
	if err != nil {
		return fmt.Errorf("independent engine observer unavailable")
	}
	defer observer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	absent := func(ctx context.Context, name, engine string) (bool, error) {
		if engine != c.Engine {
			return false, fmt.Errorf("workspace bound to another engine")
		}
		seen, err := observer.Inspect(ctx, engineobserve.Target{Name: name})
		if err != nil {
			return false, err
		}
		return !seen.Present, nil
	}
	out, err := workspace.Recover(ctx, c.WorkspaceRegistry, time.Now(), absent)
	if err != nil {
		return fmt.Errorf("workspace recovery unconfirmed")
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// repairRemove sends the broker's exact removal of a crash-repaired
// allocation through the quarantined plugin. It retries nothing.
func repairRemove(name, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if executor.RemoveRepaired(ctx, name, id) != nil {
		return fmt.Errorf("repaired allocation removal unconfirmed")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": "1.0", "container": name, "removed": true, "cleanup_release_authorized": false})
}

// settleJournal closes the broker journal's single unfinished attempt from
// the controller's retained cleanup confirmation for exactly that container.
// It holds the journal lock, so no worker can be running on it.
func settleJournal(socket, credential, owner, sourceRoot, path, engine string) error {
	root, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil || root != sourceRoot || !filepath.IsAbs(root) {
		return fmt.Errorf("canonical source root required")
	}
	lock, err := executor.ConfiguredToolLockDigest(filepath.Join(root, "tools/scanners.lock.json"))
	if err != nil {
		return fmt.Errorf("trusted tool lock unavailable")
	}
	j, err := enginejournal.OpenExisting(path, engine)
	if err != nil {
		return fmt.Errorf("engine journal unavailable or in use")
	}
	defer j.Close()
	if attempt, open := j.OpenAttempt(); open {
		client, err := workerchannel.New(socket, credential, owner, lock)
		if err != nil {
			return fmt.Errorf("private worker channel unavailable")
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		confirmation, err := client.CleanupConfirmation(ctx, attempt)
		if err != nil {
			return fmt.Errorf("no retained cleanup confirmation covers the unfinished attempt")
		}
		if j.SettleReleased(attempt, confirmation) != nil {
			return fmt.Errorf("engine journal settlement refused")
		}
	}
	observation := j.Observe()
	if err = json.NewEncoder(os.Stdout).Encode(observation); err != nil {
		return err
	}
	if observation.Unfinished != 0 || observation.Unresolved != 0 {
		return fmt.Errorf("engine journal still unsettled")
	}
	return nil
}
