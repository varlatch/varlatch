// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
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

// freeSpace is the space free to root on path's filesystem (statfs: the
// free blocks, root's reserve included, as root writes) and the
// filesystem's device, so two paths on one filesystem are counted once.
func freeSpace(path string) (uint64, uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	var info unix.Stat_t
	if err := unix.Stat(path, &info); err != nil {
		return 0, 0, err
	}
	return uint64(st.Bfree) * uint64(st.Bsize), uint64(info.Dev), nil
}

// upgradesDir checks <dataDir>/upgrades before root writes there: absent
// (it is made, the data directory owner's), or a real directory (never a
// symbolic link root would follow) owned by the data directory's owner.
func upgradesDir(dataDir string) error {
	owner, err := os.Stat(dataDir)
	if err != nil {
		return err
	}
	ost, ok := owner.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the data directory's owner cannot be read")
	}
	dir := filepath.Join(dataDir, "upgrades")
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		_ = os.Lchown(dir, int(ost.Uid), int(ost.Gid))
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is not a directory (a link or another file): an upgrade writes only into a real directory there", dir)
	case !ok || st.Uid != ost.Uid:
		return fmt.Errorf("%s is not owned by the data directory's owner (uid %d)", dir, ost.Uid)
	}
	return nil
}
