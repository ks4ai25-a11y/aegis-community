//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package enginetls

func readIdentity(string) ([]byte, []byte, []byte, error) { return nil, nil, nil, ErrIdentity }
