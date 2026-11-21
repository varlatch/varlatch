// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockDir takes dir's migration lock (migration.lock, flock): one
// `varlatch migrate` at a time per source.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "migration.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another varlatch migrate runs on %s", dir)
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
