// SPDX-License-Identifier: Apache-2.0
package scantransport

import (
	"aegis.local/controller/internal/auth"
	"aegis.local/controller/internal/domain"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

func LoadLock(path string) (string, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() {
		return "", fmt.Errorf("scanner lock must be a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", fmt.Errorf("scanner lock unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || !os.SameFile(before, st) {
		return "", fmt.Errorf("scanner lock must be a regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return "", fmt.Errorf("scanner lock exceeds budget")
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
		return "", fmt.Errorf("invalid scanner lock")
	}
	expected := map[string]bool{"semgrep_ce": true, "osv_v2": true, "trivy": true, "syft": true, "gitleaks": true, "bandit": true}
	image := regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}$`)
	version := regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,64}$`)
	for _, tool := range lock.Tools {
		if !expected[tool.ID] || !image.MatchString(tool.Image) || !version.MatchString(tool.Version) {
			return "", fmt.Errorf("invalid scanner pin")
		}
		delete(expected, tool.ID)
	}
	return domain.Hash(b), nil
}
