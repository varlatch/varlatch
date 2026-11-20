// SPDX-License-Identifier: Apache-2.0

//go:build unix

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// lockConversion holds the host-wide conversion lock in dir (an flock, so
// a killed conversion holds it no longer) until the function it returns
// is called.
func lockConversion(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "varlatch-convert.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another varlatch migrate --from-archive is running on this host")
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
