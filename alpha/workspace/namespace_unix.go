//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package workspace

import (
	"aegis.local/source"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
)

const registryNamespaceFile = ".registry.json"

// A new namespace opts into the shared creation/close barrier protocol. Older
// workers refuse the unknown entry instead of silently using unlink-first Close.
type registryNamespace struct {
	Schema   string `json:"schema_version"`
	Domain   string `json:"domain"`
	Protocol string `json:"workspace_lease_protocol"`
	Root     string `json:"registry_root_digest"`
	UID      int    `json:"uid"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	Nonce    string `json:"nonce"`
}

func (l *registryLease) namespaceDocument(nonce string) registryNamespace {
	st := l.rootInfo.Sys().(*syscall.Stat_t)
	return registryNamespace{Schema: "1.0", Domain: "aegis-workspace-registry-namespace-v1", Protocol: "2.0", Root: source.Hash([]byte("aegis-scanner-workspace-registry-v1\n" + l.path + "\n" + strconv.Itoa(os.Geteuid()))), UID: os.Geteuid(), Device: uint64(st.Dev), Inode: uint64(st.Ino), Nonce: nonce}
}

func (l *registryLease) readNamespace() (string, os.FileInfo, error) {
	before, e := l.root.Lstat(registryNamespaceFile)
	if os.IsNotExist(e) {
		return "", nil, nil
	} // Legacy namespaces never gain a binding implicitly.
	if e != nil || !privateEntry(before, 0600) || before.Size() > 4096 {
		return "", nil, fmt.Errorf("invalid registry namespace")
	}
	f, e := l.root.OpenFile(registryNamespaceFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !privateEntry(after, 0600) || !os.SameFile(before, after) {
		return "", nil, fmt.Errorf("registry namespace identity changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return "", nil, fmt.Errorf("invalid registry namespace size")
	}
	var d registryNamespace
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return "", nil, fmt.Errorf("invalid registry namespace document")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", nil, fmt.Errorf("trailing registry namespace document")
	}
	canonical, _ := json.Marshal(d)
	nonce, e := hex.DecodeString(d.Nonce)
	if e != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != d.Nonce || d != l.namespaceDocument(d.Nonce) || !bytes.Equal(b, append(canonical, '\n')) {
		return "", nil, fmt.Errorf("registry namespace scope changed")
	}
	current, e := l.root.Lstat(registryNamespaceFile)
	if e != nil || !os.SameFile(current, after) || !privateEntry(current, 0600) {
		return "", nil, fmt.Errorf("registry namespace file changed")
	}
	return source.Hash(canonical), after, nil
}

func (l *registryLease) initializeNamespace() error {
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	b, _ := json.Marshal(l.namespaceDocument(hex.EncodeToString(nonce[:])))
	f, e := l.root.OpenFile(registryNamespaceFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(append(b, '\n'))
	if e == nil && n != len(b)+1 {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	l.namespace, l.namespaceInfo, e = l.readNamespace()
	return e
}
