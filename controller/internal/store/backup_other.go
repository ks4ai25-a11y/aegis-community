// SPDX-License-Identifier: Apache-2.0
//go:build !linux && !darwin

package store

import "os"

func backupParent(os.FileInfo) bool                        { return false }
func backupFile(os.FileInfo) bool                          { return false }
func openBackupForRead(*os.Root, string) (*os.File, error) { return nil, ErrBackup }
