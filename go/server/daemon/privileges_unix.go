// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/varlatch/varlatch/go/server/config"
)

// setIDs gives the whole process (every thread) the user uid and the group
// gid, with no other group, for good.
func setIDs(uid, gid int) error {
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid || syscall.Setuid(0) == nil {
		return fmt.Errorf("the process did not become uid %d, gid %d", uid, gid)
	}
	return nil
}

// giveFiles gives files root made in the data directory to its owner,
// through their descriptors: only root's regular files with no other name,
// and no link followed, so nothing else the owner put there changes hands.
func giveFiles(uid, gid int, paths ...string) {
	for _, path := range paths {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			continue
		}
		if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == 0 && st.Nlink == 1 {
				_ = f.Chown(uid, gid)
			}
		}
		_ = f.Close()
	}
}

// giveDataFiles gives the files varlatchd cannot start without, when root
// made them, to the data directory's owner, and nothing when not root: what
// `migrate` makes as root, and what an earlier release's commands left.
func giveDataFiles(dataDir string) {
	if os.Geteuid() != 0 {
		return
	}
	st, err := dirStat(dataDir)
	if err != nil || st.Uid == 0 {
		return
	}
	paths := make([]string, 0, len(dataFiles))
	for _, name := range dataFiles {
		paths = append(paths, filepath.Join(dataDir, name))
	}
	giveFiles(int(st.Uid), int(st.Gid), paths...)
}

// becomeOwner makes a command run as root the data directory's owner, and
// the directory's group: keep, given both, opens what is needed first. Nothing
// to do as anyone else, for a directory that is root's, and for one that
// does not exist yet (the command then says so). The directory's path is
// checked before its owner is believed.
func becomeOwner(cfg *config.Config, keep func(uid, gid int)) error {
	if os.Geteuid() != 0 {
		return nil
	}
	owner, id, err := checkClientDir(cfg.DataDir, 0)
	if err != nil {
		return err
	}
	if owner <= 0 {
		return nil
	}
	st, err := dirStat(cfg.DataDir)
	if err != nil {
		return err
	}
	if idOf(st) != id || int(st.Uid) != owner {
		return fmt.Errorf("the data directory %s changed while varlatchd was using it", cfg.DataDir)
	}
	giveDataFiles(cfg.DataDir)
	keep(owner, int(st.Gid))
	if err := setIDs(owner, int(st.Gid)); err != nil {
		return fmt.Errorf("becoming the data directory's owner: %w", err)
	}
	// No other process of that user may look into this one (its keys).
	_ = disableDumps()
	// A temporary directory that was root's alone is none now.
	if unix.Access(os.TempDir(), unix.W_OK) != nil {
		_ = os.Unsetenv("TMPDIR")
	}
	return nil
}
