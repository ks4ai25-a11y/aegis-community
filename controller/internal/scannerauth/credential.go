// SPDX-License-Identifier: BUSL-1.1
package scannerauth

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrCredential = errors.New("private worker credential delivery failed")

// EnrollFile delivers a private credential before the enrollment transaction
// commits. Existing files are never overwritten and tokens never enter stdout.
func (r *Registry) EnrollFile(owner, id string, minutes int, path string) (Worker, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Worker{}, ErrCredential
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return Worker{}, ErrCredential
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return Worker{}, ErrCredential
	}
	owned, e := f.Stat()
	if e != nil || !owned.Mode().IsRegular() {
		f.Close()
		return Worker{}, ErrCredential
	}
	committed := false
	defer func() {
		f.Close()
		if !committed {
			st, e := os.Lstat(path)
			if e == nil && st.Mode()&os.ModeSymlink == 0 && os.SameFile(owned, st) {
				os.Remove(path)
			}
		}
	}()
	if e = f.Chmod(0600); e != nil {
		return Worker{}, ErrCredential
	}
	result, e := r.enroll(owner, id, minutes, func(token string) error {
		n, e := f.WriteString(token + "\n")
		if e != nil || n != 65 {
			return ErrCredential
		}
		if e = f.Sync(); e != nil {
			return ErrCredential
		}
		st, e := os.Lstat(path)
		if e != nil || st.Mode()&os.ModeSymlink != 0 || !os.SameFile(owned, st) || st.Mode().Perm() != 0600 {
			return ErrCredential
		}
		d, e := os.Open(parent)
		if e != nil {
			return ErrCredential
		}
		defer d.Close()
		if e = d.Sync(); e != nil {
			return ErrCredential
		}
		return nil
	})
	if e != nil {
		return Worker{}, e
	}
	committed = true
	return result.Worker, nil
}
