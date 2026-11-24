// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/varlatch/varlatch/go/lib/preread"
)

// openSecretFile opens a secret file without following a symbolic link, and
// checks that it is a regular file not readable, writable or executable by
// group or others (0600 or tighter). One kept open (preread) was checked
// when it was.
func openSecretFile(path string) (*os.File, error) {
	if f, err, ok := preread.Kept(path); ok {
		return f, err
	}
	return checkedSecretFile(path)
}

// checkedSecretFile is openSecretFile of a file not kept.
func checkedSecretFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link: give the regular file itself", path)
		}
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s has mode %04o (accessible to group or others): tighten it to 0600", path, perm)
	}
	return f, nil
}

// ownedByMe is whether a file is this process's user's.
func ownedByMe(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}
