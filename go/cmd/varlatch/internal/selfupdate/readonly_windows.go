// SPDX-License-Identifier: Apache-2.0

//go:build windows

package selfupdate

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func isReadOnly(error) bool { return false }

// isHeld reports whether a rename failed as it does while another process
// has the file open without sharing its deletion. Windows also answers
// "access is denied" for some of those, as for a missing right.
func isHeld(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION, windows.ERROR_ACCESS_DENIED:
		return true
	}
	return false
}
