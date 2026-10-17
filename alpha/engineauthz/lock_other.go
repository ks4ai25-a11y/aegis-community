//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package engineauthz

func ReadLock(string) (map[string]string, []byte, error) { return nil, nil, ErrPolicy }
