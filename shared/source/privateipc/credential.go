// SPDX-License-Identifier: Apache-2.0
package privateipc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var ErrPrivate = errors.New("private broker channel unavailable")
var TokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ReadToken(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateParent(filepath.Dir(path)) != nil {
		return "", ErrPrivate
	}
	f, e := openCredential(path)
	if e != nil {
		return "", ErrPrivate
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 66))
	if e != nil || len(b) != 65 || b[64] != '\n' || !TokenPattern.Match(b[:64]) {
		return "", ErrPrivate
	}
	return string(b[:64]), nil
}
func EnrollToken(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateParent(filepath.Dir(path)) != nil {
		return ErrPrivate
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return ErrPrivate
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrPrivate
	}
	done := false
	defer func() {
		f.Close()
		if !done {
			os.Remove(path)
		}
	}()
	if _, e = f.WriteString(hex.EncodeToString(b) + "\n"); e != nil {
		return ErrPrivate
	}
	if e = f.Sync(); e != nil {
		return ErrPrivate
	}
	if e = f.Close(); e != nil {
		return ErrPrivate
	}
	parent, e := os.Open(filepath.Dir(path))
	if e != nil {
		return ErrPrivate
	}
	defer parent.Close()
	if e = parent.Sync(); e != nil {
		return ErrPrivate
	}
	done = true
	return nil
}
