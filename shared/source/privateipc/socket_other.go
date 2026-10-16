//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
package privateipc

import (
	"net"
	"os"
)

func Listen(string) (net.Listener, error)     { return nil, ErrPrivate }
func ValidateSocket(string) error             { return ErrPrivate }
func validateParent(string) error             { return ErrPrivate }
func openCredential(string) (*os.File, error) { return nil, ErrPrivate }
