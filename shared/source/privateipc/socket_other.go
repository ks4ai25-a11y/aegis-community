//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package privateipc

import (
	"net"
	"os"
)

func Listen(string) (net.Listener, error)     { return nil, ErrPrivate }
func ValidateSocket(string) error             { return ErrPrivate }
func validateParent(string) error             { return ErrPrivate }
func openCredential(string) (*os.File, error) { return nil, ErrPrivate }
