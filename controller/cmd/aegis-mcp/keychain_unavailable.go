//go:build !darwin || !cgo

// SPDX-License-Identifier: BUSL-1.1
package main

import "errors"

var errKeychainUnavailable = errors.New("Keychain storage requires the native macOS build (make mcp-keychain-build)")

func openKeychain(base, account string) (keychainStore, error) {
	return nil, errKeychainUnavailable
}

func renewKeychain(base, account string, confirm func(old, next string) error) error {
	return errKeychainUnavailable
}
