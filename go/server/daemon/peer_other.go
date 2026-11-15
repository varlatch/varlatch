// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package daemon

import "net"

// peerUID: the peer check reads SO_PEERCRED, which only Linux has; the
// control socket refuses every connection elsewhere (varlatchd serves on
// Linux only).
func peerUID(*net.UnixConn) (int, bool) { return 0, false }
