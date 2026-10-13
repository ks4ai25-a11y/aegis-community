// SPDX-License-Identifier: Apache-2.0
package source

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
)

// Bound directory enumeration itself, before WalkDir-style sorting allocates an
// unbounded list from a hostile directory. Every read is anchored to os.Root.
func walkBounded(root *os.Root, visit func(string, fs.DirEntry, error) error) error {
	count := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if depth > 64 {
			return fmt.Errorf("directory depth budget exceeded")
		}
		before, err := root.Lstat(path)
		if err != nil || !before.IsDir() {
			return fmt.Errorf("directory changed during inventory")
		}
		dir, err := openNonblocking(root, path)
		if err != nil {
			return err
		}
		actual, err := dir.Stat()
		if err != nil || !actual.IsDir() || !os.SameFile(before, actual) {
			dir.Close()
			return fmt.Errorf("directory changed during inventory")
		}
		entries := []fs.DirEntry{}
		for {
			batch, err := dir.ReadDir(256)
			count += len(batch)
			if count > 20000 {
				dir.Close()
				return fmt.Errorf("directory entry budget exceeded")
			}
			entries = append(entries, batch...)
			if err == io.EOF {
				break
			}
			if err != nil {
				dir.Close()
				return err
			}
		}
		dir.Close()
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			child := entry.Name()
			if path != "." {
				child = path + "/" + child
			}
			err := visit(child, entry, nil)
			if err == fs.SkipDir {
				continue
			}
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if err = walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(".", 0)
}
