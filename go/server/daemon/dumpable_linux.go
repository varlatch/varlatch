// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "golang.org/x/sys/unix"

// disableDumps sets PR_SET_DUMPABLE to 0: no core dump, and no ptrace or
// /proc/<pid>/mem access by other processes of the same user. The unit's
// LimitCORE=0 covers core dumps too; this also covers a varlatchd started
// by hand.
func disableDumps() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// dumpable reports PR_GET_DUMPABLE (tests).
func dumpable() (int, error) {
	return unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
}
