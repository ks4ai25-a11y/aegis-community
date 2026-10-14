// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !darwin

package scannerauth

import "aegis.local/source/scanevidence"

func (r *Registry) EnrollVerifierFile(string, string, int, string, string, string) (scanevidence.VerifierIdentity, error) {
	return scanevidence.VerifierIdentity{}, ErrCredential
}
