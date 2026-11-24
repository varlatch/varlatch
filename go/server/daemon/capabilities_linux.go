// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"

	"golang.org/x/sys/unix"
)

// noCapabilities checks that no capability is left once the process is not
// root (a securebits setting could have kept them).
func noCapabilities() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return err
	}
	for _, d := range data {
		if d.Effective != 0 || d.Permitted != 0 {
			return errors.New("capabilities are left")
		}
	}
	return nil
}
