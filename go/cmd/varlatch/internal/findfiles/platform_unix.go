// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package findfiles

import (
	"io/fs"
	"syscall"
)

// links is lstat's nlink.
func links(_ string, info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// errnoNames are libuv's names for the system errors a walk meets.
var errnoNames = map[syscall.Errno]string{
	syscall.ENOENT:       "ENOENT",
	syscall.EACCES:       "EACCES",
	syscall.EPERM:        "EPERM",
	syscall.ENOTDIR:      "ENOTDIR",
	syscall.EISDIR:       "EISDIR",
	syscall.ELOOP:        "ELOOP",
	syscall.EIO:          "EIO",
	syscall.ENAMETOOLONG: "ENAMETOOLONG",
	syscall.EMFILE:       "EMFILE",
	syscall.ENFILE:       "ENFILE",
	syscall.EBUSY:        "EBUSY",
	syscall.EINVAL:       "EINVAL",
	syscall.ENXIO:        "ENXIO",
	syscall.ENODEV:       "ENODEV",
}
