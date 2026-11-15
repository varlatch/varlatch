// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package backups

import "golang.org/x/sys/unix"

// freeSpace is the bytes an unprivileged process may still write under dir.
func freeSpace(dir string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
