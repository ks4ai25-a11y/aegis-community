// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package scannerauth

import "aegis.local/source/scanevidence"

func (r *Registry) EnrollReconcilerFile(string, string, int, string, string) (scanevidence.ReconcilerIdentity, error) {
	return scanevidence.ReconcilerIdentity{}, ErrCredential
}
