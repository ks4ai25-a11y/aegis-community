// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package executor

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"text/template"
	"time"
)

func sandboxObservationFixture(t *testing.T) (Config, SandboxExpectation, observedContainer, string) {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("positive operator UID required")
	}
	t.Setenv("DOCKER_HOST", "unix:///tmp/aegis-observer-test.sock")
	t.Setenv("DOCKER_CONTEXT", "")
	root, _ := filepath.EvalSymlinks(t.TempDir())
	registry := filepath.Join(root, "registry")
	os.Mkdir(registry, 0700)
	workspace := "run-" + strings.Repeat("a", 32)
	session := filepath.Join(registry, workspace)
	os.Mkdir(session, 0700)
	repo := filepath.Join(root, "repo")
	os.Mkdir(repo, 0700)
	os.WriteFile(filepath.Join(repo, "query.py"), []byte("static only\n"), 0600)
	opened, e := os.OpenRoot(repo)
	if e != nil {
		t.Fatal(e)
	}
	defer opened.Close()
	m, e := source.ReadRootContext(context.Background(), opened, "app_demo", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := source.Capture(context.Background(), opened, m, session)
	if e != nil {
		t.Fatal(e)
	}
	guard := filepath.Join(session, "aegis-guard-fixture")
	os.Mkdir(guard, 0700)
	guardBytes := []byte("test-only guard identity, not executed")
	os.WriteFile(filepath.Join(guard, "scanner-guard"), guardBytes, 0500)
	manifest, _ := json.Marshal(snapshot.Manifest)
	os.WriteFile(filepath.Join(guard, "input-manifest.json"), manifest, 0400)
	lockBytes, e := os.ReadFile("../../tools/scanners.lock.json")
	if e != nil {
		t.Fatal(e)
	}
	lock := filepath.Join(root, "tools.json")
	os.WriteFile(lock, lockBytes, 0600)
	tool, hash, e := resolve(lock, "bandit")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	name := "aegis-scan-" + strings.Repeat("b", 32)
	d := scanevidence.Launch{Schema: "1.1", Owner: "fixture-owner", Job: "01a138a2-18e3-7520-8f12-2fb666a6c4bb", Request: source.Hash([]byte("request")), App: "app_demo", Repository: "fixture", Map: m.Digest, Lock: hash, Version: tool.Version, Image: strings.Split(tool.Image, "@")[1], Profile: "repo_offline-network-none-v1", Duration: 120, Created: now.Format(time.RFC3339), Deadline: now.Add(time.Minute).Format(time.RFC3339), GuardSet: source.Hash([]byte("fixture set")), GuardProtocol: scanevidence.GuardProtocol, Plan: scanevidence.LaunchPlan{Tool: "bandit", Container: name, Engine: source.Hash([]byte("unix:///tmp/aegis-observer-test.sock\nfixture-engine")), Workspace: workspace, Registry: source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + registry + "\n" + strconv.Itoa(os.Geteuid()))), Snapshot: snapshot.Manifest.Digest, Guard: source.Hash(guardBytes), Architecture: "arm64"}}
	doc, _ := json.Marshal(d)
	expected := SandboxExpectation{Registry: registry, Launch: scanevidence.LaunchRecord{Digest: source.Hash(doc), Document: d}}
	a := observedContainer{NetworkNames: []string{"none"}, AutoRemove: true, IPCMode: "private", ID: strings.Repeat("c", 64), Name: "/" + name, Image: "sha256:" + strings.Repeat("d", 64), Path: "/aegis/scanner-guard", Args: []string{"bandit", "120", d.Deadline}, State: "created", ImageRef: tool.Image, User: strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid()), Entrypoint: []string{"/aegis/scanner-guard"}, Command: []string{"bandit", "120", d.Deadline}, Readonly: true, Network: "none", NetworkCount: 1, Pids: 128, Memory: 768 << 20, Swap: 768 << 20, CPUs: 1e9, CapDrop: []string{"ALL"}, Security: []string{"no-new-privileges"}, LogDriver: "none", Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=96m,uid=" + strconv.Itoa(os.Geteuid()) + ",gid=" + strconv.Itoa(os.Getegid())}, Mounts: []observedMount{{"bind", snapshot.Path, "/src", false}, {"bind", guard, "/aegis", false}}}
	metadata := filepath.Join(root, "metadata.json")
	log := filepath.Join(root, "commands.log")
	t.Setenv("AEGIS_OBSERVER_METADATA", metadata)
	t.Setenv("AEGIS_OBSERVER_COMMANDS", log)
	t.Setenv("AEGIS_OBSERVER_NAME", name)
	t.Setenv("AEGIS_OBSERVER_IMAGE", a.Image)
	docker := filepath.Join(root, "docker-fixture")
	script := "#!/bin/sh\nprintf '%s\\n' \"$3\" >> \"$AEGIS_OBSERVER_COMMANDS\"\ncase \"$3\" in\n info) echo 'linux arm64 fixture-engine';;\n ps) printf '%s\\n' \"$AEGIS_OBSERVER_NAME\";;\n inspect) cat \"$AEGIS_OBSERVER_METADATA\";;\n image) printf '%s\\n' \"$AEGIS_OBSERVER_IMAGE\";;\n *) exit 9;;\nesac\n"
	os.WriteFile(docker, []byte(script), 0700)
	writeObservationFixture(t, metadata, a)
	return Config{Docker: docker, LockPath: lock}, expected, a, metadata
}
func writeObservationFixture(t *testing.T, path string, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestSandboxObserverMatchesWithoutGrantingCleanupAuthority(t *testing.T) {
	c, x, _, _ := sandboxObservationFixture(t)
	out, e := c.InspectSandbox(context.Background(), x)
	if e != nil || !out.EngineMatched || !out.MetadataMatched || !out.GuardMatched || !out.SourceMatched || out.State != "created" {
		t.Fatal(out, e)
	}
	if out.CleanupConfirmed || out.LateStartExcluded || out.LeaseExcluded || out.AuthorityVerified {
		t.Fatal("observation became cleanup authority", out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), x.Registry) || strings.Contains(string(b), "/tmp/aegis-observer-test.sock") {
		t.Fatal("private host paths published")
	}
	commands, _ := os.ReadFile(os.Getenv("AEGIS_OBSERVER_COMMANDS"))
	for _, s := range strings.Fields(string(commands)) {
		if s != "info" && s != "ps" && s != "inspect" && s != "image" {
			t.Fatal("observer mutated engine", s)
		}
	}
}
func TestSandboxObserverRefusesChangedRuntimeMetadata(t *testing.T) {
	for _, kind := range []string{"image", "image-id", "auto-remove", "devices", "ipc", "pid", "groups", "user", "privileged", "network", "network-count", "network-name", "rootfs", "caps", "security", "memory", "swap", "cpu", "pids", "tmpfs", "args", "entrypoint", "mount-rw", "extra-mount", "duplicate-mount", "outside-mount", "state", "running", "guard-bytes", "manifest", "source-bytes", "symlink-guard"} {
		t.Run(kind, func(t *testing.T) {
			c, x, a, path := sandboxObservationFixture(t)
			switch kind {
			case "auto-remove":
				a.AutoRemove = false
			case "devices":
				a.Devices = 1
			case "ipc":
				a.IPCMode = "host"
			case "pid":
				a.PIDMode = "host"
			case "groups":
				a.ExtraGroups = 1
			case "image":
				a.ImageRef = "unapproved@sha256:" + strings.Repeat("f", 64)
			case "image-id":
				a.Image = "sha256:" + strings.Repeat("e", 64)
			case "user":
				a.User = "0:0"
			case "privileged":
				a.Privileged = true
			case "network":
				a.Network = "bridge"
			case "network-name":
				a.NetworkNames = []string{"bridge"}
			case "network-count":
				a.NetworkCount = 2
			case "rootfs":
				a.Readonly = false
			case "caps":
				a.CapAdd = []string{"SYS_ADMIN"}
			case "security":
				a.Security = nil
			case "memory":
				a.Memory++
			case "swap":
				a.Swap++
			case "cpu":
				a.CPUs++
			case "pids":
				a.Pids++
			case "tmpfs":
				a.Tmpfs["/tmp"] = "rw,exec"
			case "args":
				a.Args[2] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			case "entrypoint":
				a.Entrypoint = []string{"/bin/sh"}
			case "mount-rw":
				a.Mounts[0].RW = true
			case "extra-mount":
				a.Mounts = append(a.Mounts, observedMount{"bind", "/var/run/docker.sock", "/socket", false})
			case "duplicate-mount":
				a.Mounts = append(a.Mounts, a.Mounts[0])
			case "outside-mount":
				a.Mounts[0].Source = "/private/source-outside-registry"
			case "state":
				a.State = "restarting"
			case "running":
				a.Running = true
			case "guard-bytes":
				os.Chmod(filepath.Join(a.Mounts[1].Source, "scanner-guard"), 0700)
				os.WriteFile(filepath.Join(a.Mounts[1].Source, "scanner-guard"), []byte("changed"), 0500)
				os.Chmod(filepath.Join(a.Mounts[1].Source, "scanner-guard"), 0500)
			case "manifest":
				os.Chmod(filepath.Join(a.Mounts[1].Source, "input-manifest.json"), 0600)
				os.WriteFile(filepath.Join(a.Mounts[1].Source, "input-manifest.json"), []byte("{}"), 0400)
				os.Chmod(filepath.Join(a.Mounts[1].Source, "input-manifest.json"), 0400)
			case "source-bytes":
				os.Chmod(filepath.Join(a.Mounts[0].Source, "query.py"), 0600)
				os.WriteFile(filepath.Join(a.Mounts[0].Source, "query.py"), []byte("changed"), 0400)
			case "symlink-guard":
				os.Rename(filepath.Join(a.Mounts[1].Source, "scanner-guard"), filepath.Join(a.Mounts[1].Source, "original"))
				os.Symlink("original", filepath.Join(a.Mounts[1].Source, "scanner-guard"))
			}
			writeObservationFixture(t, path, a)
			out, e := c.InspectSandbox(context.Background(), x)
			if e == nil || out.MetadataMatched || out.CleanupConfirmed {
				t.Fatal("changed runtime accepted", kind, out, e)
			}
		})
	}
}
func TestSandboxObserverAbsenceAndEngineFailureStayUnconfirmed(t *testing.T) {
	c, x, _, _ := sandboxObservationFixture(t)
	t.Setenv("AEGIS_OBSERVER_NAME", "")
	out, e := c.InspectSandbox(context.Background(), x)
	if e != nil || out.State != "absent" || out.MetadataMatched || out.GuardMatched || out.SourceMatched || out.CleanupConfirmed {
		t.Fatal(out, e)
	}
	x.Launch.Document.Plan.Engine = source.Hash([]byte("different engine"))
	b, _ := json.Marshal(x.Launch.Document)
	x.Launch.Digest = source.Hash(b)
	out, e = c.InspectSandbox(context.Background(), x)
	if e == nil || out.EngineMatched {
		t.Fatal("wrong engine accepted", out, e)
	}
}
func TestSandboxObserverRejectsHostileAndOversizedMetadata(t *testing.T) {
	for _, raw := range []string{"{\"id\":\"a\",\"ID\":\"b\"}", "{\"unknown\":true}", "{} {}", strings.Repeat("x", 32769), "{\"id\":\"\xff\"}"} {
		c, x, _, path := sandboxObservationFixture(t)
		os.WriteFile(path, []byte(raw), 0600)
		if out, e := c.InspectSandbox(context.Background(), x); e == nil || out.MetadataMatched {
			t.Fatal("hostile metadata accepted", out)
		}
	}
}

func TestObservationContextFileIsPrivateRegularAndStrict(t *testing.T) {
	_, x, _, _ := sandboxObservationFixture(t)
	parent := filepath.Join(filepath.Dir(x.Registry), "private-context")
	os.Mkdir(parent, 0700)
	path := filepath.Join(parent, "launch.json")
	writeObservationFixture(t, path, x.Launch)
	got, e := LoadObservationLaunch(path)
	if e != nil || got.Digest != x.Launch.Digest {
		t.Fatal(got, e)
	}
	os.Chmod(path, 0644)
	if _, e = LoadObservationLaunch(path); e == nil {
		t.Fatal("public context accepted")
	}
	os.Chmod(path, 0600)
	alias := filepath.Join(parent, "alias.json")
	os.Symlink("launch.json", alias)
	if _, e = LoadObservationLaunch(alias); e == nil {
		t.Fatal("symlink context accepted")
	}
	if _, e = LoadObservationLaunch("relative.json"); e == nil {
		t.Fatal("relative context accepted")
	}
	os.WriteFile(path, []byte("{\"launch_digest\":\"a\",\"LAUNCH_DIGEST\":\"b\",\"document\":{}}"), 0600)
	if _, e = LoadObservationLaunch(path); e == nil {
		t.Fatal("duplicate context keys accepted")
	}
	os.Chmod(parent, 0755)
	if _, e = LoadObservationLaunch(path); e == nil {
		t.Fatal("nonprivate context parent accepted")
	}
	os.Chmod(parent, 0700)
}

func TestPinnedLockReaderRefusesFIFOAndSymlinkWithoutBlocking(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "lock.json")
	os.WriteFile(path, []byte("{}"), 0600)
	alias := filepath.Join(parent, "alias.json")
	os.Symlink("lock.json", alias)
	if _, e := readPinnedLockFile(alias); e == nil {
		t.Fatal("symlink lock accepted")
	}
	fifo := filepath.Join(parent, "pipe")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := readPinnedLockFile(fifo); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO lock accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO lock blocked")
	}
}

func TestSemgrepObservationRequiresIndependentRuleContext(t *testing.T) {
	c, x, a, path := sandboxObservationFixture(t)
	pin, _, e := resolve(c.LockPath, "semgrep_ce")
	if e != nil {
		t.Fatal(e)
	}
	d := x.Launch.Document
	d.Plan.Tool = "semgrep_ce"
	d.Version = pin.Version
	d.Image = strings.Split(pin.Image, "@")[1]
	a.ImageRef = pin.Image
	a.Args[0] = "semgrep_ce"
	a.Command[0] = "semgrep_ce"
	provisioned := filepath.Join(filepath.Dir(x.Registry), "rules-provisioned")
	os.Mkdir(provisioned, 0700)
	os.WriteFile(filepath.Join(provisioned, "rule.yaml"), []byte("trusted synthetic rule data\n"), 0600)
	root, e := os.OpenRoot(provisioned)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	inventory, e := source.ReadRootContext(context.Background(), root, "aegis-rules", "operator-local-rules")
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := source.Capture(context.Background(), root, inventory, filepath.Join(x.Registry, d.Plan.Workspace))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(snapshot.Manifest)
	os.WriteFile(filepath.Join(a.Mounts[1].Source, "rules-manifest.json"), b, 0400)
	a.Mounts = append(a.Mounts, observedMount{"bind", snapshot.Path, "/rules", false})
	b, _ = json.Marshal(d)
	x.Launch = scanevidence.LaunchRecord{Digest: source.Hash(b), Document: d}
	writeObservationFixture(t, path, a)
	if out, e := c.InspectSandbox(context.Background(), x); e == nil || out.MetadataMatched {
		t.Fatal("missing independent rule context accepted")
	}
	x.RulesDigest = snapshot.Manifest.Digest
	out, e := c.InspectSandbox(context.Background(), x)
	if e != nil || !out.MetadataMatched || !out.RulesMatched || !out.RulesRequired || out.CleanupConfirmed {
		t.Fatal(out, e)
	}
	os.Chmod(filepath.Join(snapshot.Path, "rule.yaml"), 0600)
	os.WriteFile(filepath.Join(snapshot.Path, "rule.yaml"), []byte("changed"), 0400)
	if out, e := c.InspectSandbox(context.Background(), x); e == nil || out.RulesMatched {
		t.Fatal("changed rules accepted", out)
	}
}

func TestSandboxObserverDoesNotDefaultMissingSafetyMetadataToFalse(t *testing.T) {
	for _, field := range []string{"privileged", "running", "cap_add"} {
		c, x, a, path := sandboxObservationFixture(t)
		b, _ := json.Marshal(a)
		var values map[string]any
		json.Unmarshal(b, &values)
		delete(values, field)
		writeObservationFixture(t, path, values)
		if out, e := c.InspectSandbox(context.Background(), x); e == nil || out.MetadataMatched {
			t.Fatal("missing safety field accepted", field, out)
		}
	}
	c, x, a, path := sandboxObservationFixture(t)
	b, _ := json.Marshal(a)
	var values map[string]any
	json.Unmarshal(b, &values)
	values["privileged"] = nil
	writeObservationFixture(t, path, values)
	if out, e := c.InspectSandbox(context.Background(), x); e == nil || out.MetadataMatched {
		t.Fatal("null privileged flag accepted", out)
	}
}

func TestObservationTemplateParsesAndDoesNotReadEnvironment(t *testing.T) {
	if _, e := template.New("metadata").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.Marshal(v); return string(b) }}).Parse(observationFormat); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{".Config.Env", ".Config.Labels", ".HostConfig.Binds", "--log", "--env-file"} {
		if strings.Contains(observationFormat, s) {
			t.Fatal("unnecessary private engine data selected", s)
		}
	}
	// Nil optional lists are represented as zero counts, without template errors.
	tmpl, e := template.New("metadata").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.Marshal(v); return string(b) }}).Parse(observationFormat)
	if e != nil {
		t.Fatal(e)
	}
	fields := map[string]any{"Id": "fixture", "Config": map[string]any{}, "HostConfig": map[string]any{}, "State": map[string]any{}, "NetworkSettings": map[string]any{}}
	var out bytes.Buffer
	if e = tmpl.Execute(&out, fields); e != nil {
		t.Fatal(e)
	}
	var actual observedContainer
	if inspectionJSON(out.Bytes(), &actual, 32768) != nil {
		t.Fatal("template did not produce valid selected JSON")
	}
	if inspectionShape(out.Bytes(), observedContainer{}) == nil {
		t.Fatal("missing scalar values became confirmed metadata")
	}
}
