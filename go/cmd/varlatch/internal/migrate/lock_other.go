// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package migrate

import "errors"

// lockDir refuses: a migration runs on the Linux host of the installation
// it migrates. Every entry point (Run, Resume, Abort, Finish, Rollback)
// takes the lock first, so nothing is read or written elsewhere: on macOS
// a run would otherwise get past the barrier and fail at the live open,
// varlatchd's control socket checking its peer with SO_PEERCRED, which
// only Linux has.
func lockDir(string) (func(), error) {
	return nil, errors.New("varlatch migrate runs on the Linux host of the installation it migrates")
}
