// SPDX-License-Identifier: Apache-2.0

//go:build unix

package backup

import (
	"os"
	"syscall"
)

// openHold opens the hold to read: never through a link, never waiting for
// a pipe's writer.
func openHold(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// holdOwned is whether the hold is root's or the data directory's owner's:
// the users a restore runs as.
func holdOwned(dir string, info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	d, err := os.Stat(dir)
	if !ok || err != nil {
		return false
	}
	owner, ok := d.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == owner.Uid)
}
