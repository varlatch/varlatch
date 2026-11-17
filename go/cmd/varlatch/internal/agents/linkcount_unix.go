// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agents

import (
	"io/fs"
	"syscall"
)

// linkCount is how many names a file has (a hard link has more than one).
func linkCount(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
