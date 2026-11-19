// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openNoFollow opens a file for reading, for `import --delete-source`, as
// O_NOFOLLOW does elsewhere: a symbolic link or other reparse point at the
// path is opened itself, not followed (FILE_FLAG_OPEN_REPARSE_POINT), so
// the caller's Stat of what was opened sees it and refuses it. The handle
// shares deletion (FILE_SHARE_DELETE): Windows removes no file that is
// open without it, and the caller removes the file while it still holds
// it open, so the file it checked is the file it removes.
func openNoFollow(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(longPath(path))
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

// longPath is path as CreateFile takes a path of any length: a long
// absolute one with the `\\?\` prefix (`\\?\UNC\` for a share), which
// turns off the 260-character limit, as the os package does for its own
// calls (fixLongPath); syscall.CreateFile adds nothing. A short path, one
// that has a prefix already, or one that cannot be made absolute is given
// as it is.
func longPath(path string) string {
	// The os package's threshold: a directory's path may not exceed
	// MAX_PATH less 12 (an 8.3 file name), whatever the file's own name.
	const short = 248
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return path
	}
	// The length that counts is the full path's: a short relative path in
	// a deep working directory is a long one.
	abs, err := filepath.Abs(path) // cleaned, with backslashes, as the prefix needs
	if err != nil || len(abs) < short {
		return path
	}
	if strings.HasPrefix(abs, `\\`) {
		return `\\?\UNC\` + abs[2:]
	}
	return `\\?\` + abs
}
