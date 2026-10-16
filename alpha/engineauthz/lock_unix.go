//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
package engineauthz

import (
	"io"
	"os"
	"syscall"
)

// ReadLock accepts only a bounded regular non-linked operator file. It never
// blocks reading a FIFO or follows a substituted symlink.
func ReadLock(path string) (map[string]string, []byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Size() > 65536 || before.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, nil, ErrPolicy
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, nil, ErrPolicy
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, nil, ErrPolicy
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return nil, nil, ErrPolicy
	}
	var lock struct {
		Schema    string `json:"schema_version"`
		Resolved  string `json:"resolved_at"`
		Signature string `json:"signature_review"`
		Tools     []struct {
			ID       string `json:"id"`
			Image    string `json:"image"`
			Version  string `json:"version"`
			Upstream string `json:"upstream"`
			License  string `json:"license_review"`
		} `json:"tools"`
	}
	if strict(b, &lock, 65536) != nil || lock.Schema != "1.0" || len(lock.Tools) != 6 {
		return nil, nil, ErrPolicy
	}
	images := map[string]string{}
	for _, tool := range lock.Tools {
		if !knownTools[tool.ID] || !pinPattern.MatchString(tool.Image) || images[tool.ID] != "" {
			return nil, nil, ErrPolicy
		}
		images[tool.ID] = tool.Image
	}

	return images, b, nil
}
