// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID is the user id of the process at the other end of a control
// socket connection, from SO_PEERCRED.
func peerUID(c *net.UnixConn) (int, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return 0, false
	}
	return int(cred.Uid), true
}
