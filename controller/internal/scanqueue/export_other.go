// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !darwin

package scanqueue

import "os"

func privateExportParent(string) (*os.Root, error) { return nil, ErrInput }
