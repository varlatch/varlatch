// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import (
	"fmt"
	"io/fs"
	"os"
)

// openSecretFile opens a secret file, refusing symbolic links and
// non-regular files.
func openSecretFile(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link: give the regular file itself", path)
	}
	f, err := os.Open(path)
	if err != nil {
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
	return f, nil
}

// ownedByMe: no owner to tell; nothing is swept.
func ownedByMe(fs.FileInfo) bool { return false }

// giveToOwner: no owner to give files to.
func giveToOwner(string, int) {}
