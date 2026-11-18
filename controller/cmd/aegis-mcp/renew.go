//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func renewFile(base, path string) error {
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	info, statErr := os.Stat(parent)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || err != nil || canonical != parent || statErr != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("use a paired token file in a private directory")
	}
	unlock, err := lockRenewal(path + ".renew-lock")
	if err != nil {
		return err
	}
	defer unlock()
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
	if err := confirmRotation(base, old, next); err != nil {
		return err
	}
	if err = os.Rename(pending, path); err != nil {
		return errors.New("replacement is active; retry to install the saved credential")
	}
	if err = syncCredentialDirectory(parent); err != nil {
		return errors.New("replacement installed but directory sync failed")
	}
	return nil
}

func lockRenewal(path string) (func(), error) {
	lock, err := unix.Open(path, unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_RDWR|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("could not open credential renewal lock")
	}
	var st unix.Stat_t
	if unix.Fstat(lock, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Uid != uint32(os.Geteuid()) ||
		unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = unix.Close(lock)
		return nil, errors.New("credential renewal is already running or its lock is unavailable")
	}
	return func() { _ = unix.Close(lock) }, nil
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
	if err != nil || len(raw) >= 128 || !pairedTokenShape.MatchString(token) {
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
