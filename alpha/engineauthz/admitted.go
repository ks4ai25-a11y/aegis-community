// SPDX-License-Identifier: BUSL-1.1
package engineauthz

import (
	"aegis.local/alpha/executor"
	"aegis.local/alpha/workerchannel"
	"aegis.local/alpha/workspace"
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"context"
	"encoding/json"
	"github.com/moby/moby/api/types/container"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var admittedID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type AdmittedConfig struct {
	Socket, Credential, Owner, Authorizer, Registry, Namespace, LockPath, RulesDigest string
}
type admittedGate struct {
	client                           *workerchannel.AuthorizerClient
	config                           AdmittedConfig
	work, engine, lock, policy, seal string
	binding                          scanevidence.MutationBindingRecord
	versions                         map[string]string
}

// AdmittedPolicyDigest is a read-only provisioning input, independent of the
// later selected binding digest. The serving journal seals both identities.
func AdmittedPolicyDigest(c Config, v AdmittedConfig) (string, error) {
	if !admittedID.MatchString(v.Authorizer) || c.UID <= 0 || c.UID != os.Geteuid() || c.GID != os.Getegid() || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || !canonicalDir(c.WorkRoot) || !canonicalDir(c.JournalRoot) || v.Owner == "" || len(v.Owner) > 128 || !hashPattern.MatchString(c.EngineDigest) || !hashPattern.MatchString(v.Registry) || !hashPattern.MatchString(v.Namespace) || (v.RulesDigest != "" && !hashPattern.MatchString(v.RulesDigest)) {
		return "", ErrPolicy
	}
	for _, path := range []string{v.Socket, v.Credential} {
		parent, e := filepath.EvalSymlinks(filepath.Dir(path))
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || e != nil || parent != filepath.Dir(path) {
			return "", ErrPolicy
		}
	}
	registry := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + c.WorkRoot + "\n" + strconv.Itoa(c.UID)))
	if registry != v.Registry {
		return "", ErrPolicy
	}
	namespace, e := workspace.RegistryNamespace(context.Background(), c.WorkRoot)
	if e != nil || namespace != v.Namespace {
		return "", ErrPolicy
	}
	images, raw, e := ReadLock(v.LockPath)
	if e != nil || len(c.Images) == 0 || len(c.Images) > 6 {
		return "", ErrPolicy
	}
	for tool, image := range c.Images {
		if images[tool] != image {
			return "", ErrPolicy
		}
	}
	seal, e := json.Marshal(struct {
		Domain                      string
		Config                      AdmittedConfig
		Work, Journal, Engine, Lock string
		UID, GID                    int
		Images                      map[string]string
	}{"aegis-controller-admitted-policy-v1", v, c.WorkRoot, c.JournalRoot, c.EngineDigest, source.Hash(raw), c.UID, c.GID, c.Images})
	if e != nil {
		return "", ErrPolicy
	}
	return source.Hash(seal), nil
}
func openAdmitted(c Config, v AdmittedConfig) (*admittedGate, error) {
	policy, e := AdmittedPolicyDigest(c, v)
	if e != nil {
		return nil, e
	}
	_, raw, e := ReadLock(v.LockPath)
	if e != nil {
		return nil, ErrPolicy
	}
	lock := source.Hash(raw)
	client, e := workerchannel.NewAuthorizer(v.Socket, v.Credential, v.Owner, v.Authorizer, c.EngineDigest, v.Registry, policy, v.Namespace, lock)
	if e != nil {
		return nil, ErrPolicy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	binding, e := client.Binding(ctx)
	if e != nil {
		client.Close()
		return nil, ErrPolicy
	}
	var tools struct {
		Tools []struct{ ID, Version string }
	}
	if json.Unmarshal(raw, &tools) != nil {
		client.Close()
		return nil, ErrPolicy
	}
	versions := map[string]string{}
	for _, t := range tools.Tools {
		versions[t.ID] = t.Version
	}
	b, _ := json.Marshal(struct{ Domain, Policy, Binding string }{"aegis-controller-admitted-journal-v1", policy, binding.Digest})
	return &admittedGate{client: client, config: v, work: c.WorkRoot, engine: c.EngineDigest, lock: lock, policy: policy, seal: source.Hash(b), binding: binding, versions: versions}, nil
}
func (g *admittedGate) prepare(ctx context.Context, name, operation string, raw []byte) (scanevidence.AuthorizerLaunch, error) {
	namespace, e := workspace.RegistryNamespace(ctx, g.work)
	if e != nil || namespace != g.config.Namespace {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	_, lock, e := ReadLock(g.config.LockPath)
	if e != nil || source.Hash(lock) != g.lock {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	d, e := g.client.Launch(ctx, name, operation)
	if e != nil || d.Binding.Digest != g.binding.Digest {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	if operation == "remove" {
		return d, nil
	}
	launch, p := d.Launch.Document, d.Launch.Document.Plan
	var create container.CreateRequest
	if strict(raw, &create, 65536) != nil || create.Config == nil || create.HostConfig == nil || len(create.Cmd) != 3 || len(create.HostConfig.Mounts) < 2 || len(create.HostConfig.Mounts) > 3 {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	deadline, e := time.Parse(time.RFC3339Nano, launch.Deadline)
	if e != nil || !deadline.After(time.Now()) || launch.Lock != g.lock || p.Engine != g.engine || p.Registry != g.config.Registry || p.Architecture != runtime.GOARCH || create.Cmd[0] != p.Tool || create.Cmd[1] != strconv.Itoa(launch.Duration) || create.Cmd[2] != deadline.UTC().Format(time.RFC3339Nano) || launch.Version != g.versions[p.Tool] || !strings.HasSuffix(create.Image, "@"+launch.Image) {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	paths := map[string]string{}
	for _, m := range create.HostConfig.Mounts {
		if m.Type != "bind" || !m.ReadOnly || paths[m.Target] != "" {
			return scanevidence.AuthorizerLaunch{}, ErrPolicy
		}
		paths[m.Target] = m.Source
	}
	rules := ""
	if p.Tool == "semgrep_ce" {
		rules = g.config.RulesDigest
		if !hashPattern.MatchString(rules) {
			return scanevidence.AuthorizerLaunch{}, ErrPolicy
		}
	}
	if executor.CheckLaunchFiles(ctx, executor.SandboxExpectation{Launch: d.Launch, Registry: g.work, RulesDigest: rules}, paths["/src"], paths["/aegis"], paths["/rules"]) != nil {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	namespace, e = workspace.RegistryNamespace(ctx, g.work)
	if e != nil || namespace != g.config.Namespace || ctx.Err() != nil {
		return scanevidence.AuthorizerLaunch{}, ErrPolicy
	}
	return d, nil
}
func (g *admittedGate) intent(d scanevidence.AuthorizerLaunch, descriptor, engineID string) (scanevidence.MutationIntent, error) {
	r := scanevidence.MutationRequest{Generation: d.Generation.ID, Job: d.Generation.Job, Tool: d.Launch.Document.Plan.Tool, Operation: d.Operation, Launch: d.Launch.Digest, Descriptor: descriptor, EngineID: engineID}
	return scanevidence.NewMutationIntent(r, d.Workspace.Digest, d.Launch.Document.Plan.Container)
}
func (g *admittedGate) admit(ctx context.Context, d scanevidence.AuthorizerLaunch, expected scanevidence.MutationIntent) error {
	a, e := g.client.Admit(ctx, d, expected.Request.Descriptor, expected.Request.EngineID)
	if e != nil || a.Replay || a.Intent != expected || ctx.Err() != nil {
		return ErrPolicy
	}
	return nil
}
