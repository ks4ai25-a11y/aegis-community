// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package executor

import (
	"aegis.local/source/scanevidence"
	"os"
)

func LoadObservationLaunch(string) (scanevidence.LaunchRecord, error) {
	return scanevidence.LaunchRecord{}, ErrObservation
}
func readPinnedLockFile(string) ([]byte, error) { return nil, ErrObservation }

func inspectionRoot(string, os.FileMode) (*os.Root, error)              { return nil, ErrObservation }
func inspectionChild(string, string, string) (*os.Root, error)          { return nil, ErrObservation }
func inspectionFile(*os.Root, string, os.FileMode, int) ([]byte, error) { return nil, ErrObservation }
