// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agents

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// linkCount is how many names the open file has (a hard link has more
// than one).
func linkCount(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink), nil
	}
	return 1, nil
}

// newFileMode is the mode writeFileSync gives a new file: 0666 less the
// umask. Linux reports the umask in /proc/self/status; elsewhere it is read
// by setting it and putting it back.
func newFileMode() os.FileMode {
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if value, ok := strings.CutPrefix(line, "Umask:"); ok {
				if mask, err := strconv.ParseUint(strings.TrimSpace(value), 8, 32); err == nil {
					return os.FileMode(0o666 &^ mask)
				}
			}
		}
	}
	mask := syscall.Umask(0)
	syscall.Umask(mask)
	return os.FileMode(0o666 &^ mask)
}
