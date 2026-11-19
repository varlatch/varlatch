// SPDX-License-Identifier: Apache-2.0

//go:build windows

package findfiles

import (
	"io/fs"
	"syscall"
)

// links is lstat's nlink: the file's link count, read through a handle
// opened for its attributes only (never its contents), on the link itself
// when it is one.
func links(path string, _ fs.FileInfo) uint64 {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 1
	}
	h, err := syscall.CreateFile(p, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 1
	}
	defer syscall.CloseHandle(h)
	var data syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(h, &data) != nil {
		return 1
	}
	return uint64(data.NumberOfLinks)
}

// errnoNames are libuv's names for the Windows errors a walk meets.
var errnoNames = map[syscall.Errno]string{
	syscall.ERROR_FILE_NOT_FOUND: "ENOENT",
	syscall.ERROR_PATH_NOT_FOUND: "ENOENT",
	syscall.ERROR_ACCESS_DENIED:  "EPERM",
	syscall.Errno(267):           "ENOTDIR", // ERROR_DIRECTORY
}
