// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/varlatch/varlatch/go/server/config"
)

// setIDs gives the whole process (every thread) the user uid and the group
// gid, with no other group and no capability, for good.
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
	groups, err := syscall.Getgroups()
	if err != nil {
		return err
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid || len(groups) != 0 || syscall.Setuid(0) == nil {
		return fmt.Errorf("the process did not become uid %d, gid %d", uid, gid)
	}
	return noCapabilities()
}

// becomeOwner makes a command run as root the data directory's owner, and
// the directory's group. Before that, while it is root: keep opens what only
// root may read, the trusted certificates are loaded (SSL_CERT_FILE may be
// root's), and what root made in the directory, in an earlier release's
// commands, is given to the owner. Nothing to do as anyone else, for a
// directory that is root's, and for one that does not exist yet (the
// command then says so). The directory's path is checked before its owner
// is believed, and the directory itself held by its descriptor from then.
func becomeOwner(cfg *config.Config, keep func()) error {
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
	dir, err := pinDir(cfg.DataDir, id, owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	st, err := fstat(dir)
	if err != nil {
		return err
	}
	keep()
	_, _ = x509.SystemCertPool()
	if err := giveLeftovers(dir, int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	if err := setIDs(owner, int(st.Gid)); err != nil {
		return fmt.Errorf("becoming the data directory's owner: %w", err)
	}
	// No other process of that user may look into this one (its keys).
	if err := disableDumps(); err != nil {
		return fmt.Errorf("becoming the data directory's owner: refusing to be dumped: %w", err)
	}
	// What was root's environment is none of the owner's.
	syscall.Umask(0o077)
	if err := os.Setenv("HOME", cfg.DataDir); err != nil {
		return err
	}
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"} {
		_ = os.Unsetenv(name)
	}
	if unix.Access(os.TempDir(), unix.W_OK|unix.X_OK) != nil {
		_ = os.Unsetenv("TMPDIR")
	}
	return nil
}

// pinDir opens the directory path, which must be the one checked.
func pinDir(path string, id dirID, owner int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := fstat(f)
	if err == nil && (idOf(st) != id || int(st.Uid) != owner) {
		err = fmt.Errorf("the data directory %s changed while varlatchd was using it", path)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func fstat(f *os.File) (*syscall.Stat_t, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: no owner in its stat", f.Name())
	}
	return st, nil
}

// leftoverDepth is how deep below the data directory an earlier release's
// root-run commands made anything (.restore-work, backups and an upgrade's
// copies among it).
const leftoverDepth = 5

// giveLeftovers gives what is root's in the data directory dir to its owner.
// Each name is opened below its directory's descriptor, never through a
// link, and changed through its own: only root's, on the directory's file
// system, a directory or a file with that one name (a file with another
// name may be anything of root's, linked there). The owner cannot move in
// what is root's elsewhere. An error names what is not given, and how to.
func giveLeftovers(dir *os.File, uid, gid int) error {
	st, err := fstat(dir)
	if err != nil {
		return err
	}
	return giveIn(dir, uint64(st.Dev), uid, gid, leftoverDepth)
}

func giveIn(dir *os.File, dev uint64, uid, gid, depth int) error {
	if depth == 0 {
		return nil
	}
	if _, err := dir.Seek(0, io.SeekStart); err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := giveOne(dir, name, dev, uid, gid, depth); err != nil {
			return err
		}
	}
	return nil
}

func giveOne(dir *os.File, name string, dev uint64, uid, gid, depth int) error {
	path := filepath.Join(dir.Name(), name)
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil // gone meanwhile
		}
		return err
	}
	kind := st.Mode & unix.S_IFMT
	// A directory of the owner's may hold what root made in it.
	if uint64(st.Dev) != dev || kind != unix.S_IFDIR && (kind != unix.S_IFREG || st.Uid != 0) {
		return nil
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ELOOP) {
			return nil // another thing there now
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	open, err := fstat(f)
	if err != nil {
		return err
	}
	isDir := open.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if uint64(open.Dev) != dev || !isDir && (open.Mode&syscall.S_IFMT != syscall.S_IFREG || open.Nlink != 1) {
		return nil
	}
	if open.Uid == 0 {
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("%s is root's, and varlatchd's user cannot use it: chown -h %d:%d '%s' (%v)", path, uid, gid, strings.ReplaceAll(path, "'", `'\''`), err)
		}
	}
	if isDir {
		return giveIn(f, dev, uid, gid, depth-1)
	}
	return nil
}

// below is whether path, cleaned, names something below dir, as they are
// written.
func below(dir, path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(dir), abs)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
