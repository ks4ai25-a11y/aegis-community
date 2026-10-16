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

func Create(toolID, image, nameValue, sourceDir, rulesDir, guardDir string, seconds int, deadline time.Time, userID, groupID, processID int) container.CreateRequest {
	uid, gid := strconv.Itoa(userID), strconv.Itoa(groupID)
	pids := int64(128)
	mounts := []mount.Mount{{Type: mount.TypeBind, Source: sourceDir, Target: "/src", ReadOnly: true}, {Type: mount.TypeBind, Source: guardDir, Target: "/aegis", ReadOnly: true}}
	if rulesDir != "" {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: rulesDir, Target: "/rules", ReadOnly: true})
	}
	return container.CreateRequest{Config: &container.Config{Image: image, Entrypoint: []string{"/aegis/scanner-guard"}, Cmd: []string{toolID, strconv.Itoa(seconds), deadline.UTC().Format(time.RFC3339Nano)}, User: uid + ":" + gid, Env: []string{"HOME=/tmp", "SEMGREP_SEND_METRICS=off"}, AttachStdout: true, AttachStderr: true, Tty: false, Labels: map[string]string{"io.aegis.scan": nameValue, "io.aegis.operator_pid": strconv.Itoa(processID)}}, HostConfig: &container.HostConfig{AutoRemove: true, ReadonlyRootfs: true, NetworkMode: "none", IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, LogConfig: container.LogConfig{Type: "none"}, Mounts: mounts, Tmpfs: map[string]string{"/tmp": fmt.Sprint("rw,noexec,nosuid,size=96m,uid=", uid, ",gid=", gid)}, Resources: container.Resources{PidsLimit: &pids, Memory: 768 << 20, MemorySwap: 768 << 20, NanoCPUs: 1e9}}}
}
