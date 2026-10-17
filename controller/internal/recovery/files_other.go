//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package recovery

import (
	"context"
	"os"
)

type private struct {
	root *os.Root
	path string
}

func (p *private) close()                                            {}
func openPrivate(string, bool) (*private, error)                     { return nil, ErrRecovery }
func (p *private) sync() error                                       { return ErrRecovery }
func (p *private) write(string, []byte) error                        { return ErrRecovery }
func readOwned(context.Context, string, int64, bool) ([]byte, error) { return nil, ErrRecovery }
func hashOrCopy(context.Context, *private, string, *private, string, int64) (Artifact, error) {
	return Artifact{}, ErrRecovery
}
