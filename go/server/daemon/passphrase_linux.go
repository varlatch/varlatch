// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
