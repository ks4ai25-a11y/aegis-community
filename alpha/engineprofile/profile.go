// SPDX-License-Identifier: Apache-2.0
// Package engineprofile defines the one static scanner container profile.
package engineprofile

import (
	"fmt"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"strconv"
	"time"
)

// Database is an operator-provisioned advisory database (ADR 068) mounted
// read-only at a fixed target with the environment the tool needs to find it.
type Database struct {
	Source, Target string
	Env            []string
}

func Create(toolID, image, nameValue, sourceDir, rulesDir, guardDir string, seconds int, deadline time.Time, userID, groupID, processID int) container.CreateRequest {
	return CreateWithDatabase(toolID, image, nameValue, sourceDir, rulesDir, guardDir, seconds, deadline, userID, groupID, processID, nil)
}

// CreateWithDatabase is Create plus an optional read-only database mount. With a
// nil database the request is identical to Create.
func CreateWithDatabase(toolID, image, nameValue, sourceDir, rulesDir, guardDir string, seconds int, deadline time.Time, userID, groupID, processID int, db *Database) container.CreateRequest {
	uid, gid := strconv.Itoa(userID), strconv.Itoa(groupID)
	pids := int64(128)
	mounts := []mount.Mount{{Type: mount.TypeBind, Source: sourceDir, Target: "/src", ReadOnly: true}, {Type: mount.TypeBind, Source: guardDir, Target: "/aegis", ReadOnly: true}}
	if rulesDir != "" {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: rulesDir, Target: "/rules", ReadOnly: true})
	}
	env := []string{"HOME=/tmp", "SEMGREP_SEND_METRICS=off"}
	if db != nil {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: db.Source, Target: db.Target, ReadOnly: true})
		env = append(env, db.Env...)
	}
	return container.CreateRequest{Config: &container.Config{Image: image, Entrypoint: []string{"/aegis/scanner-guard"}, Cmd: []string{toolID, strconv.Itoa(seconds), deadline.UTC().Format(time.RFC3339Nano)}, User: uid + ":" + gid, Env: env, AttachStdout: true, AttachStderr: true, Tty: false, Labels: map[string]string{"io.aegis.scan": nameValue, "io.aegis.operator_pid": strconv.Itoa(processID)}}, HostConfig: &container.HostConfig{AutoRemove: true, ReadonlyRootfs: true, NetworkMode: "none", IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, LogConfig: container.LogConfig{Type: "none"}, Mounts: mounts, Tmpfs: map[string]string{"/tmp": fmt.Sprint("rw,noexec,nosuid,size=96m,uid=", uid, ",gid=", gid)}, Resources: container.Resources{PidsLimit: &pids, Memory: 768 << 20, MemorySwap: 768 << 20, NanoCPUs: 1e9}}}
}

// CreateTracked disables daemon auto-removal so the authorization response
// callback can observe the explicit successful DELETE (204). Docker's callback
// may run before error responses are serialized, so a later client-side 404
// cannot be used by this independent journal to confirm a removal.
func CreateTracked(toolID, image, nameValue, sourceDir, rulesDir, guardDir string, seconds int, deadline time.Time, userID, groupID, processID int) container.CreateRequest {
	return CreateTrackedWithDatabase(toolID, image, nameValue, sourceDir, rulesDir, guardDir, seconds, deadline, userID, groupID, processID, nil)
}

func CreateTrackedWithDatabase(toolID, image, nameValue, sourceDir, rulesDir, guardDir string, seconds int, deadline time.Time, userID, groupID, processID int, db *Database) container.CreateRequest {
	p := CreateWithDatabase(toolID, image, nameValue, sourceDir, rulesDir, guardDir, seconds, deadline, userID, groupID, processID, db)
	p.HostConfig.AutoRemove = false
	return p
}
