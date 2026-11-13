// SPDX-License-Identifier: Apache-2.0

package diskprobe

import (
	"os"

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
