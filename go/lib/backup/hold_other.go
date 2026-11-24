// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package backup

import (
	"errors"
	"os"
)

// openHold opens the hold to read, never through a link.
func openHold(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.Open(path)
}

// holdOwned: no installation runs here.
func holdOwned(string, os.FileInfo) bool { return true }
