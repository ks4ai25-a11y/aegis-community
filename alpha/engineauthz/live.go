// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"aegis.local/alpha/executor"
	"aegis.local/alpha/workerchannel"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
)

// LiveConfig is local operator configuration, never an engine request field.
// This adds controller and file preconditions to the existing durable plugin
// journal. It does not establish cancellation fencing or cleanup authority.
type LiveConfig struct {
	Socket, Credential, Owner, Verifier, Registry, LockPath, RulesDigest string
}

type liveGate struct {
	client             *workerchannel.VerifierClient
	config             LiveConfig
	work, engine, lock string
	versions           map[string]string
	policy             string
}

func openLive(c Config, v LiveConfig) (*liveGate, error) {
	if c.UID != os.Geteuid() || c.GID != os.Getegid() || c.UID <= 0 || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || (v.RulesDigest != "" && !hashPattern.MatchString(v.RulesDigest)) {
		return nil, ErrPolicy
	}
	registry := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + c.WorkRoot + "\n" + strconv.Itoa(c.UID)))
	if registry != v.Registry {
		return nil, ErrPolicy
	}
	images, raw, e := ReadLock(v.LockPath)
	if e != nil {
		return nil, ErrPolicy
	}
	// The request profile and the controller comparison use the same lock.
	for tool, image := range c.Images {
		if images[tool] != image {
			return nil, ErrPolicy
		}
	}
	var lock struct {
		Tools []struct{ ID, Version string }
	}
	if json.Unmarshal(raw, &lock) != nil {
		return nil, ErrPolicy
	}
	versions := map[string]string{}
	for _, t := range lock.Tools {
		if t.Version == "" || len(t.Version) > 64 {
			return nil, ErrPolicy
		}
		versions[t.ID] = t.Version
	}
	digest := source.Hash(raw)
	client, e := workerchannel.NewVerifier(v.Socket, v.Credential, v.Owner, v.Verifier, c.EngineDigest, registry, digest)
	if e != nil {
		return nil, ErrPolicy
	}
	seal, e := json.Marshal(struct {
		Domain             string
		Config             LiveConfig
		Work, Engine, Lock string
		UID, GID           int
		Images             map[string]string
	}{"aegis-controller-live-gate-v1", v, c.WorkRoot, c.EngineDigest, digest, c.UID, c.GID, c.Images})
	if e != nil {
		client.Close()
		return nil, ErrPolicy
	}
	return &liveGate{client: client, config: v, work: c.WorkRoot, engine: c.EngineDigest, lock: digest, versions: versions, policy: source.Hash(seal)}, nil
}

func (g *liveGate) check(ctx context.Context, name string, raw []byte) error {
	if ctx.Err() != nil {
		return ErrPolicy
	}
	_, lock, e := ReadLock(g.config.LockPath)
	if e != nil || source.Hash(lock) != g.lock {
		return ErrPolicy
	}
	first, e := g.client.LiveLaunch(ctx, name)
	if e != nil {
		return ErrPolicy
	}
	var launch scanevidence.LaunchRecord
	for _, l := range first.Document.Context.Document.Launches {
		if l.Document.Plan.Container == name {
			launch = l
		}
	}
	d, p := launch.Document, launch.Document.Plan
	var create container.CreateRequest
	if strict(raw, &create, 65536) != nil || create.Config == nil || create.HostConfig == nil || len(create.Cmd) != 3 || len(create.HostConfig.Mounts) < 2 || len(create.HostConfig.Mounts) > 3 {
		return ErrPolicy
	}
	deadline, e := time.Parse(time.RFC3339Nano, d.Deadline)
	if e != nil || !deadline.After(time.Now()) || d.Schema != "1.2" || d.Lock != g.lock || p.Engine != g.engine || p.Registry != g.config.Registry || p.Architecture != runtime.GOARCH || create.Cmd[0] != p.Tool || create.Cmd[1] != strconv.Itoa(d.Duration) || create.Cmd[2] != deadline.UTC().Format(time.RFC3339Nano) || d.Version != g.versions[p.Tool] || !strings.HasSuffix(create.Image, "@"+d.Image) {
		return ErrPolicy
	}
	paths := map[string]string{}
	for _, m := range create.HostConfig.Mounts {
		if m.Type != "bind" || !m.ReadOnly || paths[m.Target] != "" {
			return ErrPolicy
		}
		paths[m.Target] = m.Source
	}
	rulesDigest := ""
	if p.Tool == "semgrep_ce" {
		rulesDigest = g.config.RulesDigest
		if !hashPattern.MatchString(rulesDigest) {
			return ErrPolicy
		}
	}
	if executor.CheckLaunchFiles(ctx, executor.SandboxExpectation{Launch: launch, Registry: g.work, RulesDigest: rulesDigest}, paths["/src"], paths["/aegis"], paths["/rules"]) != nil {
		return ErrPolicy
	}
	// File traversal can consume time. Check live authority again afterward,
	// and require unchanged immutable launch and engine/journal/broker bindings.
	last, e := g.client.LiveLaunch(ctx, name)
	if e != nil || ctx.Err() != nil || !deadline.After(time.Now()) || first.Document.EngineBinding.Digest != last.Document.EngineBinding.Digest || first.Document.JournalBinding.Digest != last.Document.JournalBinding.Digest || first.Document.BrokerBinding.Digest != last.Document.BrokerBinding.Digest {
		return ErrPolicy
	}
	for _, l := range last.Document.Context.Document.Launches {
		if l.Digest == launch.Digest && l.Document.Plan.Container == name {
			return nil
		}
	}
	return ErrPolicy
}
