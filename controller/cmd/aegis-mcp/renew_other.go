//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"io"
)

func renew(io.Writer) error {
	return errors.New("paired file renewal is supported on macOS and Linux")
}
