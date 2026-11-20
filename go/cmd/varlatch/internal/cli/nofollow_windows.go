// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"syscall"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/longpath"
)

// openNoFollow opens a file for reading, for `import --delete-source`, as
// O_NOFOLLOW does elsewhere: a symbolic link or other reparse point at the
// path is opened itself, not followed (FILE_FLAG_OPEN_REPARSE_POINT), so
// the caller's Stat of what was opened sees it and refuses it. The handle
// shares deletion (FILE_SHARE_DELETE): Windows removes no file that is
// open without it, and the caller removes the file while it still holds
// it open, so the file it checked is the file it removes.
func openNoFollow(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(longpath.Of(path))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// openNoFollowWrite opens a file for writing, creating it when it is
// missing, as O_NOFOLLOW does elsewhere: a symbolic link or other reparse
// point at the path is opened itself, not followed
// (FILE_FLAG_OPEN_REPARSE_POINT, which os.OpenFile passes to CreateFile in
// the flag's high bits, with the long-path prefix it adds itself), so the
// caller's Stat of what was opened sees it and refuses it before writing.
func openNoFollowWrite(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.FILE_FLAG_OPEN_REPARSE_POINT, perm)
}

// createNoFollow is 0 on Windows: O_EXCL (CREATE_NEW) already fails on any
// existing name, a symbolic link or other reparse point included.
const createNoFollow = 0
