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
	"sync"
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
	registryNamespace                                        string
	Path                                                     string
	mu                                                       sync.Mutex
	path, registryPath                                       string
	registryInfo, registryLockInfo, workspaceInfo, leaseInfo os.FileInfo
	cleanupPending                                           bool
	lease                                                    *os.File
	record                                                   record
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
func registry(path string) (*registryLease, error) { return openRegistry(path, true) }
func Begin(path string) (*Session, error)          { return begin(path, nil) }

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
	directory, e := lock.root.Open(".")
	if e != nil {
		return nil, e
	}
	entries, e := directory.ReadDir(3)
	directory.Close()
	if e != nil && e != io.EOF {
		return nil, e
	}
	for _, entry := range entries {
		if entry.Name() != ".registry-lock" && !(entry.Name() == registryNamespaceFile && lock.namespace != "") {
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
	if e = lock.check(); e != nil {
		return nil, e
	}
	if e = lock.root.Mkdir(filepath.Base(p), 0700); e != nil {
		return nil, e
	}
	f, e := lock.root.OpenFile(filepath.Base(p)+"/lease", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		lock.root.RemoveAll(filepath.Base(p))
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		lock.root.RemoveAll(filepath.Base(p))
		return nil, e
	}
	workspaceInfo, e := lock.root.Lstat(filepath.Base(p))
	if e != nil || !privateEntry(workspaceInfo, os.ModeDir|0700) {
		f.Close()
		return nil, fmt.Errorf("workspace identity unavailable")
	}
	leaseInfo, e := f.Stat()
	if e != nil || !privateEntry(leaseInfo, 0600) || leaseInfo.Size() != 0 {
		f.Close()
		return nil, fmt.Errorf("workspace lease identity unavailable")
	}
	s := &Session{registryNamespace: lock.namespace, Path: p, path: p, registryPath: path, registryInfo: lock.rootInfo, registryLockInfo: lock.lockInfo, workspaceInfo: workspaceInfo, leaseInfo: leaseInfo, lease: f, record: record{Version: "1.0", Created: time.Now().Unix(), Reservation: reservation}}
	dir, e := lock.root.OpenRoot(filepath.Base(p))
	if e != nil {
		s.closeLocked(lock)
		return nil, e
	}
	defer dir.Close()
	if e = s.persist(dir); e != nil {
		s.closeLocked(lock)
		return nil, e
	}
	// Persist the directory entry before any source bytes or container exist.
	d, e := lock.root.Open(".")
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	if e != nil {
		s.closeLocked(lock)
		return nil, e
	}
	return s, nil
}
func (s *Session) persist(dir *os.Root) error {
	b, e := json.Marshal(s.record)
	if e != nil {
		return e
	}
	f, e := dir.OpenFile("journal.new", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	if e = dir.Rename("journal.new", "journal.json"); e != nil {
		return e
	}
	d, e := dir.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// Bind is called and fsynced before Docker receives the run command.
func (s *Session) Bind(name, engine string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Path != s.path {
		return fmt.Errorf("workspace path changed")
	}
	if s.lease == nil || s.record.Container != "" || !containerName.MatchString(name) || !engineDigest.MatchString(engine) {
		return fmt.Errorf("invalid workspace container binding")
	}
	lock, e := openRegistry(s.registryPath, false)
	if e != nil {
		return e
	}
	defer lock.Close()
	if s.registryNamespace != lock.namespace || !os.SameFile(s.registryInfo, lock.rootInfo) || !os.SameFile(s.registryLockInfo, lock.lockInfo) {
		return fmt.Errorf("workspace registry identity changed")
	}
	if e = lock.check(); e != nil {
		return e
	}
	dir, e := lock.root.OpenRoot(filepath.Base(s.path))
	if e != nil {
		return e
	}
	defer dir.Close()
	info, e := dir.Stat(".")
	if e != nil || !privateEntry(info, os.ModeDir|0700) || !os.SameFile(info, s.workspaceInfo) {
		return fmt.Errorf("workspace identity changed")
	}
	info, e = dir.Lstat("lease")
	if e != nil || !privateEntry(info, 0600) || info.Size() != 0 || !os.SameFile(info, s.leaseInfo) {
		return fmt.Errorf("workspace lease identity changed")
	}
	s.record.Container = name
	s.record.Engine = engine
	return s.persist(dir)
}

// Close removes only this session. Caller must first confirm container absence.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease == nil && !s.cleanupPending {
		return nil
	}
	lock, e := openRegistry(s.registryPath, false)
	if e != nil {
		return e
	}
	defer lock.Close()
	return s.closeLocked(lock)
}

// closeLocked is also used by failed construction, which already holds the
// registry lock. Close the lifecycle lease BEFORE deletion while admission is
// excluded. Any uncertain lease close leaves the occupied directory intact.
func (s *Session) closeLocked(lock *registryLease) error {
	if s.registryNamespace != lock.namespace || s.Path != s.path || filepath.Dir(s.path) != lock.path || !sessionName.MatchString(filepath.Base(s.path)) || !os.SameFile(s.registryInfo, lock.rootInfo) || !os.SameFile(s.registryLockInfo, lock.lockInfo) {
		return fmt.Errorf("workspace registry identity changed")
	}
	if e := lock.check(); e != nil {
		return e
	}
	name := filepath.Base(s.path)
	info, e := lock.root.Lstat(name)
	if e != nil {
		if os.IsNotExist(e) && s.cleanupPending && s.lease == nil {
			if e = lock.sync(); e != nil {
				return e
			}
			s.cleanupPending = false
			return nil
		}
		return fmt.Errorf("workspace identity unavailable")
	}
	if !privateEntry(info, os.ModeDir|0700) || !os.SameFile(info, s.workspaceInfo) {
		return fmt.Errorf("workspace identity changed")
	}
	if s.lease != nil {
		info, e = lock.root.Lstat(name + "/lease")
		if e != nil || !privateEntry(info, 0600) || info.Size() != 0 || !os.SameFile(info, s.leaseInfo) {
			return fmt.Errorf("workspace lease identity changed")
		}
		if e = s.lease.Close(); e != nil {
			return e
		}
		s.lease = nil
		s.cleanupPending = true
	}
	if e = lock.root.RemoveAll(name); e != nil {
		return e
	}
	if e = lock.sync(); e != nil {
		return e
	}
	s.cleanupPending = false
	return nil
}

// Preserve releases the kernel lease while retaining an unconfirmed execution.
func (s *Session) Preserve() {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		if entry.Name() == ".registry-lock" || entry.Name() == registryNamespaceFile && lock.namespace != "" {
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
			if e = lock.check(); e != nil {
				return e
			}
			if e = lock.root.RemoveAll(entry.Name()); e != nil {
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
