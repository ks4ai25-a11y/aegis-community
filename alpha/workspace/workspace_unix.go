// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

// Package workspace journals private operator scanner workspaces. Kernel leases
// prevent a recovery process from deleting a live operator's source snapshot.
package workspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

var ErrOccupied = errors.New("scanner workspace registry occupied; finish or recover the existing run")

var sessionName = regexp.MustCompile(`^run-[0-9a-f]{32}$`)
var engineDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var containerName = regexp.MustCompile(`^aegis-scan-[0-9a-f]{32}$`)

type record struct {
	Version     string `json:"schema_version"`
	Created     int64  `json:"created_unix"`
	Container   string `json:"container,omitempty"`
	Engine      string `json:"engine_digest,omitempty"`
	Reservation string `json:"workspace_digest,omitempty"`
}
type Session struct {
	Path   string
	lease  *os.File
	record record
}
type Recovery struct {
	Removed  int `json:"removed"`
	Active   int `json:"active"`
	Deferred int `json:"deferred"`
}

func DefaultRoot() string {
	parent, e := filepath.EvalSymlinks(os.TempDir())
	if e != nil {
		parent = os.TempDir()
	}
	return filepath.Join(parent, fmt.Sprintf("aegis-scanner-workspaces-%d", os.Geteuid()))
}
func privateDir(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("private workspace ownership or permissions invalid")
	}
	return nil
}
func registry(path string) (*os.File, error) {
	if os.Geteuid() <= 0 {
		return nil, fmt.Errorf("non-root operator required")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("absolute workspace registry required")
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil || parent != filepath.Dir(path) {
		return nil, fmt.Errorf("canonical workspace registry parent required")
	}
	if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
		return nil, e
	}
	if e = privateDir(path); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(path, ".registry-lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, fmt.Errorf("invalid registry lock")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("workspace registry busy")
	}
	return f, nil
}
func Begin(path string) (*Session, error) { return begin(path, nil) }

// BeginReserved holds registry admission while authorization commits, before
// the run directory exists. A failed acknowledgement creates no run workspace.
func BeginReserved(path string, authorize func(string) (string, error)) (*Session, error) {
	if authorize == nil {
		return nil, fmt.Errorf("workspace reservation required")
	}
	return begin(path, authorize)
}

func begin(path string, authorize func(string) (string, error)) (*Session, error) {
	lock, e := registry(path)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	// The supported operator CLI admits one run at a time. Even an orphan with
	// a released lease blocks another scan until explicit recovery establishes
	// absence of the exact container on its original engine.
	directory, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	entries, e := directory.ReadDir(2)
	directory.Close()
	if e != nil && e != io.EOF {
		return nil, e
	}
	for _, entry := range entries {
		if entry.Name() != ".registry-lock" {
			return nil, ErrOccupied
		}
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	p := filepath.Join(path, "run-"+hex.EncodeToString(nonce))
	reservation := ""
	if authorize != nil {
		reservation, e = authorize(filepath.Base(p))
		if e != nil || !engineDigest.MatchString(reservation) {
			return nil, fmt.Errorf("workspace reservation rejected")
		}
	}
	if e = os.Mkdir(p, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(p, "lease"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		os.RemoveAll(p)
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		os.RemoveAll(p)
		return nil, e
	}
	s := &Session{Path: p, lease: f, record: record{Version: "1.0", Created: time.Now().Unix(), Reservation: reservation}}
	if e = s.persist(); e != nil {
		s.Close()
		return nil, e
	}
	// Persist the directory entry before any source bytes or container exist.
	d, e := os.Open(path)
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	if e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func (s *Session) persist() error {
	b, e := json.Marshal(s.record)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(s.Path, "journal.new"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(filepath.Join(s.Path, "journal.new"), filepath.Join(s.Path, "journal.json")); e != nil {
		return e
	}
	d, e := os.Open(s.Path)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// Bind is called and fsynced before Docker receives the run command.
func (s *Session) Bind(name, engine string) error {
	if s.lease == nil || s.record.Container != "" || !containerName.MatchString(name) || !engineDigest.MatchString(engine) {
		return fmt.Errorf("invalid workspace container binding")
	}
	s.record.Container = name
	s.record.Engine = engine
	return s.persist()
}

// Close removes only this session. Caller must first confirm container absence.
func (s *Session) Close() error {
	if s.lease == nil {
		return nil
	}
	e := os.RemoveAll(s.Path)
	s.lease.Close()
	s.lease = nil
	return e
}

// Preserve releases the kernel lease while retaining an unconfirmed execution.
func (s *Session) Preserve() {
	if s.lease != nil {
		s.lease.Close()
		s.lease = nil
	}
}

// Recover never stops containers. absent must independently confirm the exact
// journalled container is absent on the operator's selected engine.
func Recover(ctx context.Context, path string, now time.Time, absent func(context.Context, string, string) (bool, error)) (out Recovery, err error) {
	lock, e := registry(path)
	if e != nil {
		return out, e
	}
	defer lock.Close()
	dir, e := os.Open(path)
	if e != nil {
		return out, e
	}
	defer dir.Close()
	entries, e := dir.ReadDir(1001)
	if e != nil && len(entries) == 0 {
		return out, e
	}
	if len(entries) > 1000 {
		return out, fmt.Errorf("workspace recovery entry budget exceeded")
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if entry.Name() == ".registry-lock" {
			continue
		}
		if !sessionName.MatchString(entry.Name()) {
			return out, fmt.Errorf("unrecognized workspace registry entry")
		}
		p := filepath.Join(path, entry.Name())
		if e = privateDir(p); e != nil {
			return out, e
		}
		f, e := os.OpenFile(filepath.Join(p, "lease"), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return out, fmt.Errorf("workspace lease unavailable")
		}
		info, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return out, statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(stat.Uid) != os.Geteuid() {
			f.Close()
			return out, fmt.Errorf("invalid workspace lease")
		}
		if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			f.Close()
			if e == syscall.EWOULDBLOCK {
				out.Active++
				continue
			}
			return out, e
		}
		e = func() error {
			defer f.Close()
			journal, e := os.OpenFile(filepath.Join(p, "journal.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if e != nil {
				return fmt.Errorf("workspace journal unavailable")
			}
			info, e := journal.Stat()
			if e != nil {
				journal.Close()
				return e
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(stat.Uid) != os.Geteuid() || info.Size() > 4096 {
				journal.Close()
				return fmt.Errorf("invalid private workspace journal")
			}
			b, e := io.ReadAll(io.LimitReader(journal, 4097))
			journal.Close()
			if e != nil || len(b) > 4096 {
				return fmt.Errorf("invalid workspace journal budget")
			}
			var r record
			if json.Unmarshal(b, &r) != nil || r.Version != "1.0" || r.Created <= 0 || (r.Reservation != "" && !engineDigest.MatchString(r.Reservation)) || (r.Container != "" && (!containerName.MatchString(r.Container) || !engineDigest.MatchString(r.Engine))) {
				return fmt.Errorf("invalid workspace journal")
			}
			// Independent guard max 120 seconds plus conservative launch/cleanup grace.
			if now.Unix()-r.Created < 180 {
				out.Deferred++
				return nil
			}
			if r.Container != "" {
				if absent == nil {
					return fmt.Errorf("container absence verifier required")
				}
				ok, e := absent(ctx, r.Container, r.Engine)
				if e != nil {
					return e
				}
				if !ok {
					out.Deferred++
					return nil
				}
			}
			if e = os.RemoveAll(p); e != nil {
				return e
			}
			out.Removed++
			return nil
		}()
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
