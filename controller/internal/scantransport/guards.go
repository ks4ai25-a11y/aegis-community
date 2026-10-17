// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"aegis.local/source"
	"aegis.local/source/scanevidence"
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LoadGuards hashes only the two fixed packaged artifacts. It never accesses
// Docker and never interprets worker-supplied paths or digests as build authority.
func LoadGuards(dir string) (scanevidence.GuardSet, error) {
	canonical, e := filepath.EvalSymlinks(dir)
	if e != nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || canonical != dir {
		return scanevidence.GuardSet{}, fmt.Errorf("canonical packaged guard directory required")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return scanevidence.GuardSet{}, fmt.Errorf("packaged guards unavailable")
	}
	defer root.Close()
	digests := map[string]string{}
	for arch, machine := range map[string]uint16{"amd64": 62, "arm64": 183} {
		name := "scanner-guard-linux-" + arch
		before, e := root.Lstat(name)
		if e != nil || !before.Mode().IsRegular() {
			return scanevidence.GuardSet{}, fmt.Errorf("packaged guard must be regular")
		}
		f, e := openGuard(root, name)
		if e != nil {
			return scanevidence.GuardSet{}, fmt.Errorf("packaged guard unavailable")
		}
		after, e := f.Stat()
		if e != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
			f.Close()
			return scanevidence.GuardSet{}, fmt.Errorf("packaged guard identity changed")
		}
		b, e := io.ReadAll(io.LimitReader(f, (32<<20)+1))
		f.Close()
		if e != nil || len(b) < 64 || len(b) > 32<<20 || string(b[:4]) != "\x7fELF" || b[4] != 2 || b[5] != 1 || binary.LittleEndian.Uint16(b[18:20]) != machine {
			return scanevidence.GuardSet{}, fmt.Errorf("packaged guard architecture or budget invalid")
		}
		info, e := buildinfo.Read(bytes.NewReader(b))
		if e != nil || info.GoVersion != "go1.27.1" || info.Path != "aegis.local/alpha/cmd/scanner-guard" {
			return scanevidence.GuardSet{}, fmt.Errorf("packaged guard build identity invalid")
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["GOOS"] != "linux" || settings["GOARCH"] != arch || settings["CGO_ENABLED"] != "0" || settings["-trimpath"] != "true" || settings["vcs"] != "" {
			return scanevidence.GuardSet{}, fmt.Errorf("packaged guard build settings invalid")
		}
		digests[arch] = source.Hash(b)
	}
	return scanevidence.NewGuardSet(digests["amd64"], digests["arm64"])
}
