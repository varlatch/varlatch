// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package doctor

import "golang.org/x/sys/unix"

// freeSpace is the space this process may still use on dir's filesystem.
func freeSpace(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// clockSynced reads the kernel's time status without changing it
// (adjtimex with no mode bits): TIME_ERROR or STA_UNSYNC means the clock
// is not synchronized.
func clockSynced() (synced, known bool) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return false, false
	}
	return state != unix.TIME_ERROR && tx.Status&unix.STA_UNSYNC == 0, true
}
