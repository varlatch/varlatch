// SPDX-License-Identifier: Apache-2.0

//go:build unix

package preread

import (
	"os"

	"golang.org/x/sys/unix"
)

// dup is another descriptor of f (the same open file: its offset is
// shared), whatever the process may open now.
func dup(f *os.File) (*os.File, error) {
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), f.Name()), nil
}
