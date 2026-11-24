// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
)

// handOver gives the files of dir named here, which a command run as root
// may have made, dir's owner and group: the user varlatchd runs as. The
// directory is that user's, so no link is followed there, and only a
// regular file with no other name is changed. As anyone but root a file is
// its maker's, and dir's owner made it.
func handOver(dir string, names ...string) {
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, name := range names {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink == 1 && (st.Uid != owner.Uid || st.Gid != owner.Gid) {
				_ = f.Chown(int(owner.Uid), int(owner.Gid))
			}
		}
		_ = f.Close()
	}
}
