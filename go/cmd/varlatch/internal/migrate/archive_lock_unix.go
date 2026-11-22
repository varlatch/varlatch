// SPDX-License-Identifier: Apache-2.0

//go:build unix

package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// defaultLockDir is where the host-wide conversion lock lives, whatever
// TMPDIR says: /run/lock when this user may write it, else /tmp.
// conversionSupported: Linux and macOS run the converter.
const conversionSupported = true

func defaultLockDir() string {
	if syscall.Access("/run/lock", 2 /* W_OK */) == nil {
		return "/run/lock"
	}
	return "/tmp"
}

// lockConversion holds the host-wide conversion lock in dir (an flock, so
// a killed conversion holds it no longer) until the function it returns
// is called. The file is opened read-only and made readable by everyone,
// so a conversion by another user locks the same file: one conversion per
// host.
func lockConversion(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "varlatch-convert.lock"), os.O_RDONLY|os.O_CREATE, 0o666)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another varlatch migrate --from-archive is running on this host (one conversion per host)")
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
