// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin || freebsd || openbsd || netbsd

package daemon

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
