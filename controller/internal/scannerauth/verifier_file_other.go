// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package scannerauth

import "aegis.local/source/scanevidence"

func (r *Registry) EnrollVerifierFile(string, string, int, string, string, string) (scanevidence.VerifierIdentity, error) {
	return scanevidence.VerifierIdentity{}, ErrCredential
}
