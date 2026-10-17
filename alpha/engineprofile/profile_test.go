// SPDX-License-Identifier: BUSL-1.1
package engineprofile

import (
	"reflect"
	"testing"
	"time"
)

func TestDatabaseMountIsReadOnlyAndOptional(t *testing.T) {
	d := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	plain := CreateTracked("trivy", "img", "aegis-scan-x", "/s", "", "/g", 60, d, 1, 1, 1)
	if !reflect.DeepEqual(plain, CreateTrackedWithDatabase("trivy", "img", "aegis-scan-x", "/s", "", "/g", 60, d, 1, 1, 1, nil)) {
		t.Fatal("nil database changed the profile")
	}
	p := CreateTrackedWithDatabase("osv_v2", "img", "aegis-scan-x", "/s", "", "/g", 60, d, 1, 1, 1, &Database{Source: "/dbroot/osv", Target: "/db/osv", Env: []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv"}})
	m := p.HostConfig.Mounts[len(p.HostConfig.Mounts)-1]
	if m.Source != "/dbroot/osv" || m.Target != "/db/osv" || !m.ReadOnly || p.Config.Env[len(p.Config.Env)-1] != "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db/osv" || p.HostConfig.NetworkMode != "none" || p.HostConfig.AutoRemove {
		t.Fatal(p.HostConfig.Mounts, p.Config.Env)
	}
}
