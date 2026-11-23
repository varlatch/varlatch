// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package setup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// noFollow refuses a symbolic link where a file is opened.
const noFollow = syscall.O_NOFOLLOW

// readNoFollow reads a file, never through a symbolic link (O_NOFOLLOW),
// at most 1 MiB.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link", path)
		}
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
