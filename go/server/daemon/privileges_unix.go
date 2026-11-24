// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
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
func becomeOwner(cfg *config.Config, keep func(), stderr io.Writer) error {
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
	left, err := giveLeftovers(dir, int(st.Uid), int(st.Gid))
	if err != nil {
		return err
	}
	if len(left) > 0 {
		fmt.Fprintf(stderr, "varlatchd: left as it is in the data directory, root's and not varlatchd's: %s\n", strings.Join(left, ", "))
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

// giveLeftovers gives what earlier releases' root-run commands made in the
// data directory dir (leftovers) to its owner. Each name is opened below its
// directory's descriptor, never through a link, and changed through its own:
// only root's, on the directory's file system, a directory or a file with
// that one name (a file with another name may be anything of root's, linked
// there). What else of root's is in the directories it looks in stays, and
// is named. An error names what is not given, and how to.
func giveLeftovers(dir *os.File, uid, gid int) (left []string, err error) {
	st, err := fstat(dir)
	if err != nil {
		return nil, err
	}
	g := giver{dev: uint64(st.Dev), uid: uid, gid: gid}
	err = g.in(dir, "")
	return g.left, err
}

type giver struct {
	dev      uint64
	uid, gid int
	left     []string
}

// in gives what is in dir, whose path below the data directory is rel.
func (g *giver) in(dir *os.File, rel string) error {
	if _, err := dir.Seek(0, io.SeekStart); err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := g.one(dir, name, path.Join(rel, name)); err != nil {
			return err
		}
	}
	return nil
}

// leave notes what stays root's.
func (g *giver) leave(p string) { g.left = append(g.left, strconv.Quote(p)) }

func (g *giver) one(dir *os.File, name, rel string) error {
	full := filepath.Join(dir.Name(), name)
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil // gone meanwhile
		}
		return err
	}
	kind := st.Mode & unix.S_IFMT
	if kind != unix.S_IFDIR && st.Uid != 0 {
		return nil
	}
	if !isLeftover(rel) || uint64(st.Dev) != g.dev || kind != unix.S_IFDIR && kind != unix.S_IFREG {
		// A directory of the owner's that is none of those is varlatchd's
		// own, which never was root's, or the owner's.
		if st.Uid == 0 {
			g.leave(full)
		}
		return nil
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ELOOP) {
			return nil // another thing there now
		}
		return fmt.Errorf("%s: %w", full, err)
	}
	f := os.NewFile(uintptr(fd), full)
	defer f.Close()
	open, err := fstat(f)
	if err != nil {
		return err
	}
	isDir := open.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if uint64(open.Dev) != g.dev || !isDir && (open.Mode&syscall.S_IFMT != syscall.S_IFREG || open.Nlink != 1) {
		if open.Uid == 0 {
			g.leave(full)
		}
		return nil
	}
	if open.Uid == 0 {
		if err := f.Chown(g.uid, g.gid); err != nil {
			return fmt.Errorf("%s is root's, and varlatchd's user cannot use it: chown -h %d:%d '%s' (%v)", full, g.uid, g.gid, strings.ReplaceAll(full, "'", `'\''`), err)
		}
	}
	if isDir {
		return g.in(f, rel)
	}
	return nil
}

// rootsAlone is whether only root may change the directory dir and where its
// path leads: every directory and link on it is root's, and not writable by
// others.
func rootsAlone(dir string) bool {
	st, err := checkPath(dir, func(uid uint32) bool { return uid == 0 })
	return err == nil && st.Uid == 0
}

// rootsOnlyName is whether a file is root's and has one name.
func rootsOnlyName(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && st.Nlink == 1
}

// fileAndDirectory is whether the descriptor f is a regular file's and dir a
// directory's. Neither is taken over unless both are; then no program this
// one starts gets them.
func fileAndDirectory(f, dir int) bool {
	var fi, di unix.Stat_t
	if unix.Fstat(f, &fi) != nil || unix.Fstat(dir, &di) != nil || fi.Mode&unix.S_IFMT != unix.S_IFREG || di.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	unix.CloseOnExec(f)
	unix.CloseOnExec(dir)
	return true
}

// createAlone makes a file that must not be there.
func createAlone(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}
