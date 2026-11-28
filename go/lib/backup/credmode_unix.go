// SPDX-License-Identifier: Apache-2.0

//go:build unix

package backup

import (
	"io/fs"
	"syscall"
)

// FileGID is a file's group.
func FileGID(info fs.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}
