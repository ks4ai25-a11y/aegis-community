// SPDX-License-Identifier: BUSL-1.1
package scantransport

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"aegis.local/controller/internal/scanqueue"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func LoadLock(path string) (string, error) { d, _, e := LoadPins(path); return d, e }

// LoadPins binds pin metadata and file digest from the same bounded read.
func LoadPins(path string) (string, map[string]scanqueue.Pin, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() {
		return "", nil, fmt.Errorf("scanner lock must be a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", nil, fmt.Errorf("scanner lock unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || !os.SameFile(before, st) {
		return "", nil, fmt.Errorf("scanner lock must be a regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return "", nil, fmt.Errorf("scanner lock exceeds budget")
	}
	var lock struct {
		Schema    string `json:"schema_version"`
		Resolved  string `json:"resolved_at"`
		Signature string `json:"signature_review"`
		Tools     []struct {
			ID       string `json:"id"`
			Version  string `json:"version"`
			Image    string `json:"image"`
			Upstream string `json:"upstream"`
			License  string `json:"license_review"`
		} `json:"tools"`
	}
	r, _ := http.NewRequest("POST", "http://localhost", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if auth.Decode(r, &lock) != nil || lock.Schema != "1.0" || len(lock.Tools) != 6 {
		return "", nil, fmt.Errorf("invalid scanner lock")
	}
	expected := map[string]bool{"semgrep_ce": true, "osv_v2": true, "trivy": true, "syft": true, "gitleaks": true, "bandit": true}
	image := regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$`)
	version := regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,64}$`)
	pins := map[string]scanqueue.Pin{}
	for _, tool := range lock.Tools {
		if !expected[tool.ID] || !image.MatchString(tool.Image) || !version.MatchString(tool.Version) {
			return "", nil, fmt.Errorf("invalid scanner pin")
		}
		pins[tool.ID] = scanqueue.Pin{Version: tool.Version, Image: strings.Split(tool.Image, "@")[1]}
		delete(expected, tool.ID)
	}
	return domain.Hash(b), pins, nil
}
