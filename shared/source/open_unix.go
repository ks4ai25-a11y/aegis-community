//go:build linux || darwin

package source

import (
	"os"
	"syscall"
)

// A file replaced by a FIFO must not block a read-only inventory worker.
func openNonblocking(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
