//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
package engineauthz

func ReadLock(string) (map[string]string, []byte, error) { return nil, nil, ErrPolicy }
