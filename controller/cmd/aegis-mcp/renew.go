//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

var pairedFileToken = regexp.MustCompile(`^aegis_dp_[0-9a-f]{64}$`)

func renew(status io.Writer) error {
	base, err := consoleBase()
	if err != nil {
		return err
	}
	path := os.Getenv("AEGIS_CONNECTOR_TOKEN_FILE")
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Stat(parent)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || err != nil || canonical != parent || statErr != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("use a paired token file in a private directory")
	}
	lock, err := unix.Open(path+".renew-lock", unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_RDWR|unix.O_NONBLOCK, 0600)
	if err != nil {
		return errors.New("could not open credential renewal lock")
	}
	defer unix.Close(lock)
	var st unix.Stat_t
	if unix.Fstat(lock, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Uid != uint32(os.Geteuid()) ||
		unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("credential renewal is already running or its lock is unavailable")
	}
	old, err := readPairedToken(path)
	if err != nil {
		return errors.New("paired connector credential unavailable")
	}
	pending := path + ".renewal"
	next, err := readPairedToken(pending)
	if errors.Is(err, os.ErrNotExist) {
		secret, e := pairingSecret()
		if e != nil {
			return errors.New("could not generate replacement credential")
		}
		next = "aegis_dp_" + secret
		err = storePairedCredential(pending, next)
	}
	if err != nil || next == old || syncCredentialDirectory(parent) != nil {
		return errors.New("private renewal file unavailable")
	}
	c := &client{base: base, token: old, http: connectorHTTPClient()}
	defer c.http.CloseIdleConnections()
	digest := pairingHash("aegis-paired-token-v1\x00" + next)
	body, _ := json.Marshal(map[string]string{"credential_digest": digest})
	raw, err := c.request(http.MethodPost, "/desktop/renew", body, "")
	var receipt struct {
		ID      string `json:"connector_id"`
		Expires int64  `json:"expires_unix"`
	}
	if err == nil && (json.Unmarshal([]byte(raw), &receipt) != nil || receipt.ID == "" || receipt.Expires <= 0) {
		err = errors.New("renewal response was invalid")
	}
	// The response can be lost after commit. Prove the locally saved replacement
	// is already active before promoting it, including after the receipt expires.
	c.token = next
	verified, lookup := c.get("/desktop/status")
	var device struct {
		ID            string `json:"connector_id"`
		Scope         string `json:"scope"`
		Authenticated bool   `json:"authenticated"`
	}
	if lookup != nil || json.Unmarshal([]byte(verified), &device) != nil || !device.Authenticated || device.Scope != "desktop_handoff_v1" ||
		device.ID == "" || (receipt.ID != "" && device.ID != receipt.ID) {
		if err == httpStatusError(http.StatusNotFound) {
			return errors.New("approve renewal for this device in Aegis, then retry")
		}
		return errors.New("renewal could not be verified; retry with the same token file")
	}
	if err = os.Rename(pending, path); err != nil {
		return errors.New("replacement is active; retry to install the saved credential")
	}
	if err = syncCredentialDirectory(parent); err != nil {
		return errors.New("replacement installed but directory sync failed")
	}
	fmt.Fprintln(status, "Renewed. Start a new desktop app session and call aegis_status.")
	return nil
}

func readPairedToken(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return "", errors.New("credential must be a private owned file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 128))
	token := strings.TrimSpace(string(raw))
	if err != nil || len(raw) >= 128 || !pairedFileToken.MatchString(token) {
		return "", errors.New("invalid paired credential")
	}
	return token, nil
}

func syncCredentialDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
