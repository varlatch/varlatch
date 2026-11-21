// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"io/fs"
	"syscall"
)

// statOwner is the owner's uid of a file, -1 when unknown.
func statOwner(st fs.FileInfo) int {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid)
	}
	return -1
}
