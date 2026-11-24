// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// lock holds the configuration directory's upgrade lock (upgrade.lock,
// flock), so two upgrades never run at once. What an upgrade starts inherits
// it (Upgrader.bind): killed, it leaves the lock held until what it started
// has ended, so that nothing of it goes on beside a recovery.
func lock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "upgrade.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the upgrade lock in %s: %v", dir, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another varlatch upgrade is running on this host, or a command that a killed one started: wait until it has ended")
		}
		return nil, fmt.Errorf("cannot take the upgrade lock: %v", err)
	}
	return f, nil
}

// lockData takes the lock file path, which is there.
func lockData(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// ownerToBe is the data directory's owner and group, and whether this
// process must become them to work there: run as root, for a directory that
// is not root's.
func ownerToBe(dataDir string) (uid, gid uint32, child bool, err error) {
	info, err := os.Lstat(dataDir)
	if err != nil {
		return 0, 0, false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return 0, 0, false, fmt.Errorf("%s is not a directory", dataDir)
	}
	return st.Uid, st.Gid, os.Geteuid() == 0 && st.Uid != 0, nil
}

// asOwner runs cmd as the user uid and the group gid, with no other group.
func asOwner(cmd *exec.Cmd, uid, gid uint32) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
}

func killSelf() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL); select {} }

// rootOwned checks that no one but root (or the user who runs this, a
// test's) can change what path leads to: path, every directory above it and
// every one a link in it leads through is theirs, and not writable by
// others, but for a directory with the sticky bit (/tmp), above path, where
// only an entry's owner renames it.
func rootOwned(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for _, p := range []string{path, real} {
		if p, err = filepath.Abs(p); err != nil {
			return err
		}
		for at := p; ; at = filepath.Dir(at) {
			info, err := os.Lstat(at)
			if err != nil {
				return err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			switch {
			case !ok:
				return fmt.Errorf("%s: no owner in its stat", at)
			case st.Uid != 0 && int(st.Uid) != os.Geteuid():
				return fmt.Errorf("%s is not root's (uid %d): no binary below it is run or kept as root", at, st.Uid)
			case info.Mode()&os.ModeSymlink != 0:
				// Its own bits mean nothing; its directory's do.
			case info.Mode().Perm()&0o022 != 0 && (at == p || info.Mode()&os.ModeSticky == 0):
				return fmt.Errorf("%s may be written by others (mode %04o): no binary below it is run or kept as root (chmod go-w)", at, info.Mode().Perm())
			}
			if at == filepath.Dir(at) {
				break
			}
		}
	}
	return nil
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
