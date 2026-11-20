// SPDX-License-Identifier: Apache-2.0

//go:build windows

package findfiles

import (
	"io/fs"
	"syscall"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/longpath"
)

// links is lstat's nlink: the file's link count, read through a handle
// opened for its attributes only (never its contents), on the link itself
// when it is one.
func links(path string, _ fs.FileInfo) uint64 {
	p, err := syscall.UTF16PtrFromString(longpath.Of(path))
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

// errnoNames are libuv's names for the Windows errors a walk meets, as
// uv_translate_sys_error gives them: libuv v1.52.1 (bundled by Node.js
// 26.12.1 and 26.13.1), src/win/error.c lines 134-142 (ERROR_BAD_PATHNAME,
// ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME,
// ERROR_INVALID_DRIVE and ERROR_PATH_NOT_FOUND are UV_ENOENT) and line 158
// (ERROR_ACCESS_DENIED is UV_EPERM). So a name Windows does not allow, such
// as one holding a control character, does not exist for Node.js.
// In src/win/fs.c, UV_ENOTDIR is set only for opendir or scandir on a file
// (lines 1632 and 1603), which the walk says itself with errNotDirectory
// (Go's syscall.ENOTDIR is ERROR_PATH_NOT_FOUND on Windows).
var errnoNames = map[syscall.Errno]string{
	syscall.Errno(161):           "ENOENT", // ERROR_BAD_PATHNAME
	syscall.Errno(267):           "ENOENT", // ERROR_DIRECTORY
	syscall.ERROR_FILE_NOT_FOUND: "ENOENT",
	syscall.Errno(123):           "ENOENT", // ERROR_INVALID_NAME
	syscall.Errno(15):            "ENOENT", // ERROR_INVALID_DRIVE
	syscall.ERROR_PATH_NOT_FOUND: "ENOENT",
	syscall.ERROR_ACCESS_DENIED:  "EPERM",
}
