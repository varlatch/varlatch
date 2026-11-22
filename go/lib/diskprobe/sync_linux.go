// SPDX-License-Identifier: Apache-2.0

package diskprobe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// datasync flushes the file's data the way SQLite does on Linux
// (fdatasync), without forcing a metadata update the WAL does not need.
func datasync(f *os.File) error {
	for {
		err := unix.Fdatasync(int(f.Fd()))
		if err != unix.EINTR {
			return err
		}
	}
}

// unnamedFile is a file without a name in dir (O_TMPFILE): its blocks are
// dir's filesystem's, and closing it frees them.
func unnamedFile(dir string) (*os.File, error) {
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnnamed
		}
		return nil, fmt.Errorf("diskprobe: %w", &os.PathError{Op: "open", Path: dir, Err: err})
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir, unnamedName)), nil
}
