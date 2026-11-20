// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// owned gives path the data directory owner's user and group (the
// varlatch user's, so the varlatchd it runs as can use what root made).
// Best effort: as anyone but root, a file is already its maker's.
func owned(path, dataDir string) {
	info, err := os.Stat(dataDir)
	if err != nil {
		return
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(path, int(st.Uid), int(st.Gid))
	}
}

// lock holds the configuration directory's upgrade lock (upgrade.lock,
// flock), so two upgrades never run at once.
func lock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "upgrade.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the upgrade lock in %s: %v", dir, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another varlatch upgrade is running on this host")
		}
		return nil, fmt.Errorf("cannot take the upgrade lock: %v", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
