//go:build !linux && !darwin

package source

import (
	"fmt"
	"os"
)

func openNonblocking(root *os.Root, path string) (*os.File, error) {
	return nil, fmt.Errorf("confined inventory is not yet supported on this platform")
}
