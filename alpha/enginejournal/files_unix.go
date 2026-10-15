// SPDX-License-Identifier: Apache-2.0
//go:build linux || darwin

package enginejournal

import (
	"aegis.local/source"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type privateRoot struct {
	root *os.Root
	lock *os.File
}

func (p *privateRoot) close() {
	if p.lock != nil {
		p.lock.Close()
	}
	p.root.Close()
}
func owned(info os.FileInfo, mode os.FileMode, dir bool) bool {
	if info == nil || info.Mode().Perm() != mode || info.IsDir() != dir {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && (dir || info.Mode().IsRegular() && st.Nlink == 1)
}
func openPrivate(path string) (*privateRoot, error) {
	before, e := os.Lstat(path)
	if e != nil || !owned(before, 0700, true) {
		return nil, ErrJournal
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrJournal
	}
	after, e := root.Stat(".")
	if e != nil || !owned(after, 0700, true) || !os.SameFile(before, after) {
		root.Close()
		return nil, ErrJournal
	}
	return &privateRoot{root: root}, nil
}
func (p *privateRoot) sync() error {
	f, e := p.root.Open(".")
	if e != nil {
		return ErrJournal
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrJournal
	}
	return nil
}
func (p *privateRoot) write(path string, b []byte) error {
	f, e := p.root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return ErrJournal
	}
	defer f.Close()
	n, e := f.Write(b)
	if e != nil || n != len(b) || f.Sync() != nil {
		return ErrJournal
	}
	if f.Close() != nil {
		return ErrJournal
	}
	return p.sync()
}
func (p *privateRoot) newDir(path string) (*privateRoot, error) {
	if p.root.Mkdir(path, 0700) != nil {
		return nil, ErrJournal
	}
	if p.sync() != nil {
		return nil, ErrJournal
	}
	root, e := p.root.OpenRoot(path)
	if e != nil {
		return nil, ErrJournal
	}
	st, e := root.Stat(".")
	if e != nil || !owned(st, 0700, true) {
		root.Close()
		return nil, ErrJournal
	}
	return &privateRoot{root: root}, nil
}
func (p *privateRoot) list(max int) ([]os.DirEntry, error) {
	f, e := p.root.Open(".")
	if e != nil {
		return nil, ErrJournal
	}
	defer f.Close()
	items, e := f.ReadDir(max + 1)
	if e != nil && e != io.EOF {
		return nil, ErrJournal
	}
	if len(items) > max {
		return nil, ErrJournal
	}
	return items, nil
}
func read[T any](p *privateRoot, path string) (envelope[T], int, error) {
	var out envelope[T]
	before, e := p.root.Lstat(path)
	if e != nil || !owned(before, 0600, false) || before.Size() > 4096 {
		return out, 0, ErrJournal
	}
	f, e := p.root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return out, 0, ErrJournal
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !owned(after, 0600, false) || !os.SameFile(before, after) {
		return out, 0, ErrJournal
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 || json.Unmarshal(b, &out) != nil {
		return out, 0, ErrJournal
	}
	canonical, e := json.Marshal(out)
	doc, _ := json.Marshal(out.Document)
	if e != nil || !bytes.Equal(bytes.TrimSpace(b), canonical) || source.Hash(doc) != out.Digest {
		return out, 0, ErrJournal
	}
	return out, len(b), nil
}
func Open(path, engine string) (*Journal, error) {
	return openJournal(path, engine, true)
}

// ReadObservation acquires the existing namespace lock without creating files
// or acknowledging requests. It reports local bookkeeping, never authority.
func ReadObservation(path, engine string) (Observation, error) {
	j, e := openJournal(path, engine, false)
	if e != nil {
		return Observation{}, e
	}
	defer j.Close()
	return j.Observe(), nil
}
func openJournal(path, engine string, create bool) (*Journal, error) {
	if os.Geteuid() <= 0 || !hash.MatchString(engine) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrJournal
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil || parent != filepath.Dir(path) {
		return nil, ErrJournal
	}
	if create {
		e = os.Mkdir(path, 0700)
	} else {
		_, e = os.Lstat(path)
	}
	if e != nil && (!create || !os.IsExist(e)) {
		return nil, ErrJournal
	}
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path {
		return nil, ErrJournal
	}
	p, e := openPrivate(path)
	if e != nil {
		return nil, e
	}
	held := false
	defer func() {
		if !held {
			p.close()
		}
	}()
	beforeLock, le := p.root.Lstat(".lock")
	if !create && le != nil {
		return nil, ErrJournal
	}
	if le != nil && !os.IsNotExist(le) || le == nil && (!owned(beforeLock, 0600, false) || beforeLock.Size() != 0) {
		return nil, ErrJournal
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE
	}
	lock, e := p.root.OpenFile(".lock", flags, 0600)
	if e != nil {
		return nil, ErrJournal
	}
	p.lock = lock
	st, e := lock.Stat()
	currentLock, ce := p.root.Lstat(".lock")
	if e != nil || ce != nil || !owned(st, 0600, false) || st.Size() != 0 || !owned(currentLock, 0600, false) || !os.SameFile(st, currentLock) || beforeLock != nil && !os.SameFile(beforeLock, st) || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrJournal
	}
	items, e := p.list(maxAttempts + 2)
	if e != nil {
		return nil, e
	}
	if _, e = p.root.Lstat("identity.json"); os.IsNotExist(e) {
		if !create {
			return nil, ErrJournal
		}
		if len(items) != 1 || items[0].Name() != ".lock" {
			return nil, ErrJournal
		}
		random := make([]byte, 16)
		if _, e = rand.Read(random); e != nil {
			return nil, e
		}
		d := wrapped(identity{Schema: "1.0", Namespace: hex.EncodeToString(random), Engine: engine, Created: time.Now().UTC().Format(time.RFC3339Nano)})
		b, _ := json.Marshal(d)
		if e = p.write("identity.json", append(b, '\n')); e != nil {
			return nil, e
		}
	}
	ident, size, e := read[identity](p, "identity.json")
	if e != nil || ident.Document.Schema != "1.0" || ident.Document.Engine != engine || !nonce.MatchString(ident.Document.Namespace) {
		return nil, ErrJournal
	}
	if _, e = time.Parse(time.RFC3339Nano, ident.Document.Created); e != nil {
		return nil, ErrJournal
	}
	j := &Journal{files: p, engine: engine, namespace: ident.Digest, bytes: size}
	items, e = p.list(maxAttempts + 2)
	if e != nil {
		return nil, e
	}
	for _, item := range items {
		if item.Name() == ".lock" || item.Name() == "identity.json" {
			continue
		}
		if !name.MatchString(item.Name()) {
			return nil, ErrJournal
		}
		before, e := p.root.Lstat(item.Name())
		if e != nil || !owned(before, 0700, true) {
			return nil, ErrJournal
		}
		root, e := p.root.OpenRoot(item.Name())
		if e != nil {
			return nil, ErrJournal
		}
		child := &privateRoot{root: root}
		after, se := root.Stat(".")
		if se != nil || !owned(after, 0700, true) || !os.SameFile(before, after) {
			child.close()
			return nil, ErrJournal
		}
		e = j.load(child, item.Name())
		child.close()
		if e != nil {
			return nil, e
		}
		j.attempts++
	}
	if j.attempts > maxAttempts || j.bytes > maxBytes {
		return nil, ErrFull
	}
	held = true
	return j, nil
}
func (j *Journal) load(p *privateRoot, containerName string) error {
	items, e := p.list(7)
	if e != nil {
		return e
	}
	allowed := map[string]bool{"attempt.json": true}
	for _, op := range []string{"create", "start", "remove"} {
		allowed[op+".pending.json"] = true
		allowed[op+".response.json"] = true
	}
	present := map[string]bool{}
	for _, item := range items {
		if !allowed[item.Name()] {
			return ErrJournal
		}
		present[item.Name()] = true
	}
	m, n, e := read[manifest](p, "attempt.json")
	j.bytes += n
	if e != nil || m.Document.Schema != "1.0" || m.Document.Name != containerName || m.Document.Engine != j.engine || m.Document.Namespace != j.namespace || !hash.MatchString(m.Document.Descriptor) {
		return ErrJournal
	}
	created, e := time.Parse(time.RFC3339Nano, m.Document.Created)
	if e != nil {
		return ErrJournal
	}
	previous := m.Digest
	unresolved := false
	known := ""
	started, removed := false, false
	for _, op := range []string{"create", "start", "remove"} {
		pending, reply := present[op+".pending.json"], present[op+".response.json"]
		if !pending {
			if reply {
				return ErrJournal
			}
			continue
		}
		if (op != "create" && known == "") || removed || unresolved {
			return ErrJournal
		}
		in, n, e := read[intent](p, op+".pending.json")
		j.bytes += n
		if e != nil || in.Document.Schema != "1.0" || in.Document.Manifest != m.Digest || in.Document.Previous != previous || in.Document.Operation != op || in.Document.Container != known {
			return ErrJournal
		}
		stamp, se := time.Parse(time.RFC3339Nano, in.Document.Created)
		if se != nil || stamp.Before(created) {
			return ErrJournal
		}
		if !reply {
			j.unresolved++
			unresolved = true
			if op == "create" && (present["start.pending.json"] || present["remove.pending.json"]) {
				return ErrJournal
			}
			continue
		}
		out, n, e := read[response](p, op+".response.json")
		j.bytes += n
		if e != nil || out.Document.Schema != "1.0" || out.Document.Intent != in.Digest || out.Document.Operation != op || !id.MatchString(out.Document.Container) {
			return ErrJournal
		}
		at, ae := time.Parse(time.RFC3339Nano, out.Document.Created)
		if ae != nil || at.Before(stamp) {
			return ErrJournal
		}
		previous = out.Digest
		switch op {
		case "create":
			if out.Document.Status != 201 {
				return ErrJournal
			}
			known = out.Document.Container
		case "start":
			if started || out.Document.Status != 204 || out.Document.Container != known {
				return ErrJournal
			}
			started = true
		case "remove":
			if (out.Document.Status != 204 && out.Document.Status != 404) || out.Document.Container != known {
				return ErrJournal
			}
			removed = true
		}
	}
	// Even a completed create/start needs a completed remove before this run can
	// cease blocking later attempts; a crash between writes remains uncertain.
	if !removed {
		j.unfinished++
	}
	return nil
}
