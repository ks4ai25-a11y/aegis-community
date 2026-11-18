//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import "errors"

func renewFile(base, path string) error {
	return errors.New("paired file renewal is supported on macOS and Linux")
}
