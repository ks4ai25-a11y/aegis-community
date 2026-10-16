//go:build !linux && !darwin

// SPDX-License-Identifier: Apache-2.0
package enginetls

func readIdentity(string) ([]byte, []byte, []byte, error) { return nil, nil, nil, ErrIdentity }
