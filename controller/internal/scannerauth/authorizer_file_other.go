// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !darwin

package scannerauth

import "aegis.local/source/scanevidence"

func (r *Registry) EnrollAuthorizerFile(string, string, int, string, string, string, string) (scanevidence.AuthorizerIdentity, error) {
	return scanevidence.AuthorizerIdentity{}, ErrCredential
}
