// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// openNoFollow opens a file for reading, refusing a symbolic link at the
// last component (O_NOFOLLOW).
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
