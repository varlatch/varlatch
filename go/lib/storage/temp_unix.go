// SPDX-License-Identifier: Apache-2.0

//go:build unix

package storage

import (
	"os"

	"golang.org/x/sys/unix"
)

// tempFromEnvironment: SQLite's unix VFS takes the directory from the
// environment and a fixed list.
const tempFromEnvironment = true

// usableTemp is SQLite's own test of a temporary directory: a directory
// this process may create files in (EROFS on a read-only filesystem).
func usableTemp(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir() && unix.Access(dir, unix.W_OK|unix.X_OK) == nil
}
