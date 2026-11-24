// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/varlatch/varlatch/go/server/tailnet"
)

// openSecretFile opens a secret file without following a symbolic link, and
// checks that it is a regular file not readable, writable or executable by
// group or others (0600 or tighter).
func openSecretFile(path string) (*os.File, error) {
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

// giveToOwner gives the node's files a node command created as root (its
// state directory, the pin, the hold, the listeners report, the lock, and
// a restore's takeover journal and issuance count) to the data directory's
// owner, so the varlatchd that later serves as that user can read them.
// Nothing when not root, or when root owns the data directory. Symbolic
// links are changed themselves, never followed.
func giveToOwner(dataDir string, owner int) {
	if os.Getuid() != 0 || owner <= 0 {
		return
	}
	st, err := os.Stat(dataDir)
	if err != nil {
		return
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != owner {
		return
	}
	gid := int(s.Gid)
	for _, name := range []string{tailnet.PinFile, tailnet.HoldFile, tailnet.ListenersFile, LockFile, TakeoverFile, IssuanceFile} {
		_ = os.Lchown(filepath.Join(dataDir, name), owner, gid)
	}
	_ = filepath.WalkDir(filepath.Join(dataDir, tailnet.StateDir), func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			_ = os.Lchown(path, owner, gid)
		}
		return nil
	})
}
