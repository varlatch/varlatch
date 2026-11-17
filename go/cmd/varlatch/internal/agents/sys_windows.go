// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agents

import (
	"os"
	"syscall"
)

// linkCount is how many names the open file has (a hard link has more
// than one).
func linkCount(f *os.File) (uint64, error) {
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &d); err != nil {
		return 0, err
	}
	return uint64(d.NumberOfLinks), nil
}

// newFileMode is the mode a new file gets; Windows keeps only its
// read-only bit.
func newFileMode() os.FileMode { return 0o666 }
