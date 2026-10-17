// SPDX-License-Identifier: BUSL-1.1
package ingest

import (
	"fmt"
	"os"
	"syscall"
)

func FileIdentity(_ string, st os.FileInfo) string {
	if v, ok := st.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", v.Dev, v.Ino)
	}
	return fmt.Sprintf("%d", st.ModTime().UnixNano())
}
