// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !darwin

package store

import "os"

func backupParent(os.FileInfo) bool                        { return false }
func backupFile(os.FileInfo) bool                          { return false }
func openBackupForRead(*os.Root, string) (*os.File, error) { return nil, ErrBackup }
