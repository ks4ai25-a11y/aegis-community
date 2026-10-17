// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package scanqueue

import "os"

func privateExportParent(string) (*os.Root, error) { return nil, ErrInput }
