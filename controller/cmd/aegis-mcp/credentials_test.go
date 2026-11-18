// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCredentialLocationRejectsConflictingConfiguration(t *testing.T) {
	t.Setenv("AEGIS_CONNECTOR_TOKEN_FILE", "/private/token")
	t.Setenv("AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT", "work-device")
	if _, _, err := credentialLocation(); err == nil {
		t.Fatal("accepted file and Keychain settings together")
	}
	t.Setenv("AEGIS_CONNECTOR_TOKEN_FILE", "")
	t.Setenv("AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT", "work/device")
	if _, _, err := credentialLocation(); err == nil {
		t.Fatal("accepted malformed Keychain account")
	}
	t.Setenv("AEGIS_CONNECTOR_KEYCHAIN_ACCOUNT", "work-device")
	if path, account, err := credentialLocation(); err != nil || path != "" || account != "work-device" {
		t.Fatal("did not select only the Keychain account")
	}
}

type testKeychain struct {
	current, pending string
	removeErr        error
}

func (s *testKeychain) read(pending bool) (string, error) {
	value := s.current
	if pending {
		value = s.pending
	}
	if value == "" {
		return "", errKeychainItemMissing
	}
	return value, nil
}

func (s *testKeychain) add(pending bool, token string) error {
	if !pending || s.pending != "" {
		return errors.New("unexpected test write")
	}
	s.pending = token
	return nil
}

func (s *testKeychain) replace(token string) error {
	s.current = token
	return nil
}

func (s *testKeychain) clearPending() error {
	if s.removeErr != nil {
		return s.removeErr
	}
	s.pending = ""
	return nil
}
func (s *testKeychain) close() {}

func TestKeychainRotationResumesWithSavedCandidate(t *testing.T) {
	old := "aegis_dp_" + strings.Repeat("1", 64)
	s := &testKeychain{current: old}
	if err := checkKeychainPairingSlot(s); err == nil {
		t.Fatal("allowed pairing over an existing credential")
	}
	interrupted := errors.New("interrupted")
	if err := rotateKeychain(s, func(current, next string) error {
		if current != old || !pairedTokenShape.MatchString(next) || next == current {
			t.Fatal("incorrect replacement")
		}
		return interrupted
	}); !errors.Is(err, interrupted) {
		t.Fatal("did not report interruption")
	}
	candidate := s.pending
	if candidate == "" || s.current != old {
		t.Fatal("did not preserve the pending replacement and old credential")
	}
	s.removeErr = interrupted
	if err := rotateKeychain(s, func(current, next string) error {
		if current != old || next != candidate {
			t.Fatal("did not reuse the candidate")
		}
		return nil
	}); !errors.Is(err, interrupted) || s.current != candidate || s.pending != candidate {
		t.Fatal("did not retain the installed credential when cleanup failed")
	}
	s.removeErr = nil
	if err := rotateKeychain(s, func(_, _ string) error {
		t.Fatal("tried to rotate an already installed replacement")
		return nil
	}); err != nil || s.current != candidate || s.pending != "" {
		t.Fatal("did not finish the interrupted cleanup")
	}
}
