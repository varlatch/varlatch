// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockDataDir takes the data directory's lifetime lock without waiting
// (flock on varlatchd.lock, exclusive): serve holds it for its whole life,
// an offline host command while it runs. The kernel releases it when the
// process ends, however it ends, so a crash never leaves it held.
func lockDataDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errLocked
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
