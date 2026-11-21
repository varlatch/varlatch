// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os"
	"syscall"
)

// keepOwner gives f old's owner and group, as root (a file root replaces
// for its service keeps the service's ownership).
func keepOwner(f *os.File, old os.FileInfo) {
	if st, ok := old.Sys().(*syscall.Stat_t); ok && asRoot() {
		_ = f.Chown(int(st.Uid), int(st.Gid))
	}
}
