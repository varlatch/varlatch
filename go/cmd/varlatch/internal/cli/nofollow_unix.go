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

// openNoFollowWrite opens a file for writing, creating it (mode perm, less
// the umask) when it is missing, and refuses a symbolic link at the last
// component, dangling or not (O_NOFOLLOW: ELOOP), so nothing is written
// through one.
func openNoFollowWrite(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, perm)
}

// createNoFollow refuses a symbolic link at the last component when a file
// is created (credential issue's --out); O_EXCL refuses an existing one too.
const createNoFollow = syscall.O_NOFOLLOW
