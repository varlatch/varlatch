// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/varlatch/varlatch/go/server/tailnet"
)

// ownedByMe is whether a file is this process's user's.
func ownedByMe(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}

// giveToOwner gives the node's files a node command created as root (its
// state directory, the pin, the hold, the listeners report, the lock) to
// the data directory's owner, so the varlatchd that later serves as that
// user can read them. Nothing when not root, or when root owns the data
// directory. Symbolic links are changed themselves, never followed.
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
	for _, name := range []string{tailnet.PinFile, tailnet.HoldFile, tailnet.ListenersFile, LockFile} {
		_ = os.Lchown(filepath.Join(dataDir, name), owner, gid)
	}
	_ = filepath.WalkDir(filepath.Join(dataDir, tailnet.StateDir), func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			_ = os.Lchown(path, owner, gid)
		}
		return nil
	})
}
