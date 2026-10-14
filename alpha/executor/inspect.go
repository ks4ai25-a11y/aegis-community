// SPDX-License-Identifier: Apache-2.0
package executor

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ErrObservation = errors.New("scanner sandbox observation refused")
var observationHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var observationID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var observationWorkspace = regexp.MustCompile(`^run-[0-9a-f]{32}$`)

type SandboxExpectation struct {
	Launch scanevidence.LaunchRecord
	// Registry and RulesDigest come from trusted operator provisioning. They
	// are not accepted from browser input or treated as authority by this API.
	Registry    string
	RulesDigest string
}
type SandboxObservation struct {
	Tool              string   `json:"tool_id,omitempty"`
	RulesRequired     bool     `json:"rules_snapshot_required"`
	Schema            string   `json:"schema_version"`
	At                string   `json:"observed_at"`
	Launch            string   `json:"launch_digest"`
	Engine            string   `json:"engine_digest"`
	Name              string   `json:"container_name"`
	Container         string   `json:"container_id,omitempty"`
	State             string   `json:"container_state"`
	Code              string   `json:"observation_code"`
	EngineMatched     bool     `json:"original_engine_matched"`
	MetadataMatched   bool     `json:"container_metadata_matched"`
	GuardMatched      bool     `json:"reported_guard_file_matched"`
	SourceMatched     bool     `json:"reported_source_snapshot_matched"`
	RulesMatched      bool     `json:"reported_rules_snapshot_matched"`
	AuthorityVerified bool     `json:"controller_authority_verified"`
	LeaseExcluded     bool     `json:"active_workspace_lease_excluded"`
	LateStartExcluded bool     `json:"late_start_excluded"`
	CleanupConfirmed  bool     `json:"cleanup_confirmed"`
	Limits            []string `json:"limitations"`
}

type observedMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}
type observedContainer struct {
	NetworkNames   []string `json:"network_names"`
	AutoRemove     bool     `json:"auto_remove"`
	Devices        int      `json:"devices"`
	DeviceRequests int      `json:"device_requests"`
	DeviceRules    int      `json:"device_rules"`
	ExtraGroups    int      `json:"extra_groups"`
	PIDMode        string   `json:"pid_mode"`
	IPCMode        string   `json:"ipc_mode"`
	UTSMode        string   `json:"uts_mode"`
	UsernsMode     string   `json:"userns_mode"`

	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Image        string            `json:"image_id"`
	Path         string            `json:"path"`
	Args         []string          `json:"args"`
	State        string            `json:"state"`
	Running      bool              `json:"running"`
	ImageRef     string            `json:"image_ref"`
	User         string            `json:"user"`
	Entrypoint   []string          `json:"entrypoint"`
	Command      []string          `json:"command"`
	Readonly     bool              `json:"readonly"`
	Privileged   bool              `json:"privileged"`
	Network      string            `json:"network"`
	NetworkCount int               `json:"network_count"`
	Pids         int64             `json:"pids"`
	Memory       int64             `json:"memory"`
	Swap         int64             `json:"swap"`
	CPUs         int64             `json:"nano_cpus"`
	CapAdd       []string          `json:"cap_add"`
	CapDrop      []string          `json:"cap_drop"`
	Security     []string          `json:"security"`
	LogDriver    string            `json:"log_driver"`
	Tmpfs        map[string]string `json:"tmpfs"`
	Mounts       []observedMount   `json:"mounts"`
}

// Select metadata explicitly: never read Config.Env, labels, secrets, command
// output, logs or unrelated containers. Mount paths remain private in memory.
const observationFormat = `{"id":{{json .Id}},"name":{{json .Name}},"image_id":{{json .Image}},"path":{{json .Path}},"args":{{json .Args}},"state":{{json .State.Status}},"running":{{json .State.Running}},"image_ref":{{json .Config.Image}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"auto_remove":{{json .HostConfig.AutoRemove}},"devices":{{if .HostConfig.Devices}}{{len .HostConfig.Devices}}{{else}}0{{end}},"device_requests":{{if .HostConfig.DeviceRequests}}{{len .HostConfig.DeviceRequests}}{{else}}0{{end}},"device_rules":{{if .HostConfig.DeviceCgroupRules}}{{len .HostConfig.DeviceCgroupRules}}{{else}}0{{end}},"extra_groups":{{if .HostConfig.GroupAdd}}{{len .HostConfig.GroupAdd}}{{else}}0{{end}},"pid_mode":{{json .HostConfig.PidMode}},"ipc_mode":{{json .HostConfig.IpcMode}},"uts_mode":{{json .HostConfig.UTSMode}},"userns_mode":{{json .HostConfig.UsernsMode}},"network":{{json .HostConfig.NetworkMode}},"network_count":{{if .NetworkSettings.Networks}}{{len .NetworkSettings.Networks}}{{else}}0{{end}},"network_names":[{{$separator:=""}}{{range $name,$net:=.NetworkSettings.Networks}}{{$separator}}{{json $name}}{{$separator = ","}}{{end}}],"pids":{{json .HostConfig.PidsLimit}},"memory":{{json .HostConfig.Memory}},"swap":{{json .HostConfig.MemorySwap}},"nano_cpus":{{json .HostConfig.NanoCpus}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"log_driver":{{json .HostConfig.LogConfig.Type}},"tmpfs":{{json .HostConfig.Tmpfs}},"mounts":[{{range $i,$m:=.Mounts}}{{if $i}},{{end}}{"Type":{{json $m.Type}},"Source":{{json $m.Source}},"Destination":{{json $m.Destination}},"RW":{{json $m.RW}}}{{end}}]}`

func inspectOutput(ctx context.Context, docker, endpoint string, limit int, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := &cappedOutput{limit: limit, cancel: cancel}
	var cmd *exec.Cmd
	if endpoint == "" {
		cmd = exec.CommandContext(bounded, docker, args...)
		cmd.Env = dockerEnv()
	} else {
		cmd = engineCommand(bounded, docker, endpoint, args...)
	}
	cmd.Stdout = out
	stderr := &cappedOutput{limit: 4096, cancel: cancel}
	cmd.Stderr = stderr
	e := cmd.Run()
	b, overflow := out.Bytes()
	_, stderrOverflow := stderr.Bytes()
	if e != nil || overflow || stderrOverflow || bounded.Err() != nil {
		return nil, ErrObservation
	}
	return b, nil
}
func inspectionPlan(x SandboxExpectation) (time.Time, error) {
	d := x.Launch.Document
	p := d.Plan
	b, e := json.Marshal(d)
	deadline, de := time.Parse(time.RFC3339Nano, d.Deadline)
	created, ce := time.Parse(time.RFC3339Nano, d.Created)
	if e != nil || len(b) > 4096 || source.Hash(b) != x.Launch.Digest || d.Schema != "1.1" || d.GuardProtocol != scanevidence.GuardProtocol || !observationHash.MatchString(d.GuardSet) || !observationHash.MatchString(p.Guard) || !observationHash.MatchString(p.Engine) || !observationHash.MatchString(p.Registry) || !observationHash.MatchString(p.Snapshot) || !observationHash.MatchString(d.Map) || !scannerName.MatchString(p.Container) || !observationWorkspace.MatchString(p.Workspace) || d.Profile != "repo_offline-network-none-v1" || d.Duration < 1 || d.Duration > 120 || de != nil || ce != nil || !deadline.After(created) || (p.Architecture != "arm64" && p.Architecture != "amd64") {
		return time.Time{}, ErrObservation
	}
	if _, e = scanevidence.BuildInvocation(p.Tool); e != nil {
		return time.Time{}, ErrObservation
	}
	if p.Tool == "semgrep_ce" && !observationHash.MatchString(x.RulesDigest) || p.Tool != "semgrep_ce" && x.RulesDigest != "" {
		return time.Time{}, ErrObservation
	}
	return deadline, nil
}

// InspectSandbox observes an exact journalled scanner name on its original
// local engine. It never creates, starts, stops, removes or releases anything.
// A supplied launch hash is context, not independently authenticated authority.
func (c Config) InspectSandbox(ctx context.Context, x SandboxExpectation) (out SandboxObservation, err error) {
	out = SandboxObservation{Schema: "1.0", At: time.Now().UTC().Format(time.RFC3339Nano), State: "unobserved", Limits: []string{
		"Point-in-time engine metadata and reported host files only; not runtime-memory or mount-inode attestation.",
		"Caller-supplied launch context is not independently authenticated controller authority.",
		"Active workspace leases, incomplete allocations and queued late starts are not excluded.",
		"Container absence or matching metadata never confirms cleanup or releases controller admission.",
	}}
	fail := func(code string) (SandboxObservation, error) { out.Code = code; return out, ErrObservation }
	deadline, e := inspectionPlan(x)
	if e != nil || os.Geteuid() <= 0 || os.Getegid() < 0 {
		return fail("PLAN_OR_PLATFORM_INVALID")
	}
	d, p := x.Launch.Document, x.Launch.Document.Plan
	out.Launch = x.Launch.Digest
	out.Name = p.Container
	out.Tool = p.Tool
	out.RulesRequired = p.Tool == "semgrep_ce"
	registry, e := inspectionRoot(x.Registry, 0700)
	if e != nil {
		return fail("REGISTRY_UNCONFIRMED")
	}
	registry.Close()
	expectedRegistry := source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + x.Registry + "\n" + strconv.Itoa(os.Geteuid())))
	if expectedRegistry != p.Registry {
		return fail("REGISTRY_UNCONFIRMED")
	}
	tool, lock, e := resolve(c.LockPath, p.Tool)
	if e != nil || lock != d.Lock || tool.Version != d.Version || strings.Split(tool.Image, "@")[1] != d.Image {
		return fail("TOOL_PIN_UNCONFIRMED")
	}
	docker, endpoint, e := c.engine(ctx)
	if e != nil {
		return fail("ENGINE_UNCONFIRMED")
	}
	b, e := inspectOutput(ctx, docker, endpoint, 512, "info", "--format", "{{.OSType}} {{.Architecture}} {{.ID}}")
	fields := strings.Fields(string(b))
	if e != nil || len(fields) != 3 || fields[0] != "linux" {
		return fail("ENGINE_UNCONFIRMED")
	}
	arch := fields[1]
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	engine := source.Hash([]byte(endpoint + "\n" + fields[2]))
	if engine != p.Engine || arch != p.Architecture {
		return fail("ENGINE_UNCONFIRMED")
	}
	out.Engine = engine
	out.EngineMatched = true
	b, e = inspectOutput(ctx, docker, endpoint, 512, "ps", "--all", "--filter", "name=^/"+p.Container+"$", "--format", "{{.Names}}")
	if e != nil {
		return fail("CONTAINER_UNCONFIRMED")
	}
	if strings.TrimSpace(string(b)) == "" {
		out.State = "absent"
		out.Code = "ABSENT_AT_OBSERVATION"
		return out, nil
	}
	if strings.TrimSpace(string(b)) != p.Container {
		return fail("CONTAINER_UNCONFIRMED")
	}
	b, e = inspectOutput(ctx, docker, endpoint, 32768, "inspect", "--type", "container", "--format", observationFormat, p.Container)
	if e != nil {
		return fail("CONTAINER_UNCONFIRMED")
	}
	var actual observedContainer
	if inspectionJSON(b, &actual, 32768) != nil {
		return fail("CONTAINER_METADATA_INVALID")
	}
	if inspectionShape(b, observedContainer{}) != nil {
		return fail("CONTAINER_FIELDS_INCOMPLETE")
	}
	var selected struct {
		Mounts []json.RawMessage `json:"mounts"`
	}
	if json.Unmarshal(b, &selected) != nil {
		return fail("CONTAINER_UNCONFIRMED")
	}
	for _, mount := range selected.Mounts {
		if inspectionShape(mount, observedMount{}) != nil {
			return fail("CONTAINER_UNCONFIRMED")
		}
	}

	if !observationID.MatchString(actual.ID) || actual.Name != "/"+p.Container || actual.ImageRef != tool.Image || !observationHash.MatchString(actual.Image) {
		return fail("CONTAINER_IDENTITY_MISMATCH")
	}
	b, e = inspectOutput(ctx, docker, endpoint, 256, "image", "inspect", "--format", "{{.Id}}", tool.Image)
	if e != nil || strings.TrimSpace(string(b)) != actual.Image {
		return fail("CONTAINER_IMAGE_MISMATCH")
	}
	switch actual.State {
	case "created", "running", "exited", "dead":
	default:
		return fail("CONTAINER_STATE_UNCONFIRMED")
	}
	if actual.Running != (actual.State == "running") {
		return fail("CONTAINER_STATE_UNCONFIRMED")
	}
	args := []string{p.Tool, strconv.Itoa(d.Duration), deadline.UTC().Format(time.RFC3339Nano)}
	if actual.Path != "/aegis/scanner-guard" || !slices.Equal(actual.Args, args) || !slices.Equal(actual.Entrypoint, []string{"/aegis/scanner-guard"}) || !slices.Equal(actual.Command, args) {
		return fail("CONTAINER_COMMAND_MISMATCH")
	}
	if !actual.AutoRemove || actual.Devices != 0 || actual.DeviceRequests != 0 || actual.DeviceRules != 0 || actual.ExtraGroups != 0 || actual.PIDMode != "" || actual.IPCMode != "private" || actual.UTSMode != "" || actual.UsernsMode != "" || !actual.Readonly || actual.Privileged || actual.Network != "none" || !((actual.State == "created" && actual.NetworkCount == 0 && len(actual.NetworkNames) == 0) || (actual.NetworkCount == 1 && slices.Equal(actual.NetworkNames, []string{"none"}))) || actual.User != fmt.Sprint(os.Geteuid(), ":", os.Getegid()) || actual.Pids != 128 || actual.Memory != 768<<20 || actual.Swap != 768<<20 || actual.CPUs != 1e9 || len(actual.CapAdd) != 0 || !slices.Equal(actual.CapDrop, []string{"ALL"}) || !slices.Equal(actual.Security, []string{"no-new-privileges"}) || actual.LogDriver != "none" {
		return fail("SANDBOX_METADATA_MISMATCH")
	}
	tmp := fmt.Sprint("rw,noexec,nosuid,size=96m,uid=", os.Geteuid(), ",gid=", os.Getegid())
	if len(actual.Tmpfs) != 1 || actual.Tmpfs["/tmp"] != tmp {
		return fail("SANDBOX_TMPFS_MISMATCH")
	}
	mounts := map[string]string{}
	for _, m := range actual.Mounts {
		if m.Type != "bind" || m.RW || mounts[m.Destination] != "" {
			return fail("SANDBOX_MOUNT_MISMATCH")
		}
		switch m.Destination {
		case "/src", "/aegis":
		case "/rules":
			if p.Tool != "semgrep_ce" {
				return fail("SANDBOX_MOUNT_MISMATCH")
			}
		default:
			return fail("SANDBOX_MOUNT_MISMATCH")
		}
		mounts[m.Destination] = m.Source
	}
	required := 2
	if p.Tool == "semgrep_ce" {
		required = 3
	}
	if len(mounts) != required || mounts["/src"] == "" || mounts["/aegis"] == "" {
		return fail("SANDBOX_MOUNT_MISMATCH")
	}
	session := filepath.Join(x.Registry, p.Workspace)
	root, e := inspectionRoot(session, 0700)
	if e != nil {
		return fail("WORKSPACE_UNCONFIRMED")
	}
	root.Close()
	sourceDir, e := inspectionChild(session, mounts["/src"], "aegis-source-")
	if e != nil {
		return fail("SOURCE_MOUNT_UNCONFIRMED")
	}
	defer sourceDir.Close()
	guardDir, e := inspectionChild(session, mounts["/aegis"], "aegis-guard-")
	if e != nil {
		return fail("GUARD_MOUNT_UNCONFIRMED")
	}
	defer guardDir.Close()
	guard, e := inspectionFile(guardDir, "scanner-guard", 0500, 16<<20)
	if e != nil || source.Hash(guard) != p.Guard {
		return fail("GUARD_FILE_MISMATCH")
	}
	out.GuardMatched = true
	manifestBytes, e := inspectionFile(guardDir, "input-manifest.json", 0400, scanevidence.MaxOutput)
	if e != nil {
		return fail("SOURCE_MANIFEST_UNCONFIRMED")
	}
	var manifest source.Manifest
	if inspectionJSON(manifestBytes, &manifest, scanevidence.MaxOutput) != nil || manifest.Digest != p.Snapshot || manifest.InputMap != d.Map || source.ValidateSnapshot(ctx, sourceDir, manifest) != nil {
		return fail("SOURCE_SNAPSHOT_MISMATCH")
	}
	out.SourceMatched = true
	if p.Tool == "semgrep_ce" {
		rules, e := inspectionChild(session, mounts["/rules"], "aegis-source-")
		if e != nil {
			return fail("RULES_MOUNT_UNCONFIRMED")
		}
		defer rules.Close()
		b, e := inspectionFile(guardDir, "rules-manifest.json", 0400, scanevidence.MaxOutput)
		if e != nil {
			return fail("RULES_MANIFEST_UNCONFIRMED")
		}
		var m source.Manifest
		if inspectionJSON(b, &m, scanevidence.MaxOutput) != nil || m.Digest != x.RulesDigest || source.ValidateSnapshot(ctx, rules, m) != nil {
			return fail("RULES_SNAPSHOT_MISMATCH")
		}
		out.RulesMatched = true
	}
	if e = ctx.Err(); e != nil {
		return fail("OBSERVATION_CANCELLED")
	}
	out.Container = actual.ID
	out.State = actual.State
	out.MetadataMatched = true
	out.Code = "MATCHED_AT_OBSERVATION"
	return out, nil
}
