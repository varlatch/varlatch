// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The data directory holds the control socket and the lock file
// (control.go), and the database. Anyone who could create or replace
// entries in it, or change where its path leads, could put a socket of
// their own in the daemon's place, take the lock, or point varlatchd at
// another directory. The lock, the socket and the database are each opened
// by path, so the path itself must be trusted, not only the directory it
// led to once:
//
//   - the configured path's last component is the directory itself, never
//     a symbolic link;
//   - the path is resolved one component at a time, following each
//     symbolic link by hand (at most 40), and everything the resolution
//     passes through is checked: every directory traversed is owned by root
//     or by a trusted user and is not writable by its group or others,
//     unless its sticky bit keeps others from replacing what they do not
//     own (/tmp); every link followed, at any hop, with a relative or an
//     absolute target, is owned by root or by a trusted user, so no one
//     else can change where it leads (macOS's /var and /tmp, root's links
//     in root's /, pass);
//   - the directory is owned by the user varlatchd runs as and writable by
//     no one else.
//
// A directory reached that way stays where it is: only root and its owner
// can move anything on the path. serve then checks again, after taking the
// lock and after binding the socket, that the path still leads to the
// same directory (its device and inode). varlatchd admin makes the same
// path checks (trusting root, itself and the directory's owner), refuses a
// socket file that is not a socket owned by the directory's owner, and,
// once connected, a server whose peer credentials are not that owner's or
// root's. The shipped unit's directory (/var/lib/varlatch, StateDirectory
// mode 0700, User=varlatch) passes.

// dirID is a directory's identity: its device and inode.
type dirID struct{ dev, ino uint64 }

// trustedOwners says which owners of an ancestor directory are trusted.
type trustedOwners func(uid uint32) bool

// checkServeDir is serve's check: the path trusted (ancestors owned by root
// or uid), the directory owned by uid and writable by no one else. It
// returns the directory's identity, to check again later (sameDir).
func checkServeDir(dir string, uid int) (dirID, error) {
	trusted := func(u uint32) bool { return u == 0 || int(u) == uid }
	st, err := checkPath(dir, trusted)
	if err != nil {
		return dirID{}, err
	}
	if int(st.Uid) != uid {
		return dirID{}, fmt.Errorf("the data directory %s is owned by uid %d, not by the user varlatchd runs as (uid %d)", dir, st.Uid, uid)
	}
	return idOf(st), nil
}

// checkClientDir is varlatchd admin's check before it connects or locks:
// the path trusted (ancestors owned by root, the caller or the directory's
// owner), the directory writable by no one but its owner and owned by the
// caller unless the caller is root (who runs commands for the service
// user), and a socket that is there a socket, not a link, owned by the
// directory's owner. It returns the directory's owner and identity. A
// directory that does not exist yet passes (owner -1): the command then
// fails as it did before.
func checkClientDir(dir string, uid int) (int, dirID, error) {
	owner, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return -1, dirID{}, nil
	}
	if err != nil {
		return 0, dirID{}, err
	}
	ownerUID := owner.Sys().(*syscall.Stat_t).Uid
	trusted := func(u uint32) bool { return u == 0 || int(u) == uid || u == ownerUID }
	st, err := checkPath(dir, trusted)
	if err != nil {
		return 0, dirID{}, err
	}
	if uid != 0 && int(st.Uid) != uid {
		return 0, dirID{}, fmt.Errorf("the data directory %s is owned by uid %d, not by you (uid %d): run the command as the user varlatchd runs as", dir, st.Uid, uid)
	}
	sock := filepath.Join(dir, ControlSocket)
	fi, err := os.Lstat(sock)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, dirID{}, err
	}
	if err == nil {
		ss, _ := fi.Sys().(*syscall.Stat_t)
		if fi.Mode()&fs.ModeSocket == 0 || ss == nil || ss.Uid != st.Uid {
			return 0, dirID{}, fmt.Errorf("%s is not a socket owned by the data directory's owner: refusing to connect through it", sock)
		}
	}
	return int(st.Uid), idOf(st), nil
}

// serverPeerAllowed is the client's check of the process that answered on
// the socket: the data directory's owner, or root.
func serverPeerAllowed(peer, owner int) bool { return peer == owner || peer == 0 }

// sameDir checks that dir still leads to the directory id names.
func sameDir(dir string, id dirID) error {
	st, err := dirStat(dir)
	if err != nil {
		return err
	}
	if idOf(st) != id {
		return fmt.Errorf("the data directory %s changed while varlatchd was using it (another directory is at its path now)", dir)
	}
	return nil
}

// checkPath checks dir's path (see the top of this file) and returns the
// directory's stat.
func checkPath(dir string, trusted trustedOwners) (*syscall.Stat_t, error) {
	if !filepath.IsAbs(dir) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		dir = abs
	}
	dir = filepath.Clean(dir)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("the data directory %s is a symbolic link: configure the directory it leads to", dir)
	}
	real, err := resolveTrusted(dir, trusted)
	if err != nil {
		return nil, fmt.Errorf("the data directory %s: %w", dir, err)
	}
	st, err := dirStat(real)
	if err != nil {
		return nil, err
	}
	if st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("the data directory %s may be written by its group or by others (mode %#o): it holds varlatchd's control socket and lock, so it must be writable by its owner only (chmod go-w)", dir, st.Mode&0o777)
	}
	return st, nil
}

// maxLinks bounds the symbolic links followed resolving one path, as the
// kernel's own limit does (ELOOP).
const maxLinks = 40

// ownerOf is a file's owner (a variable so tests can stand in for another
// user's files).
var ownerOf = func(_ string, fi fs.FileInfo) uint32 { return fi.Sys().(*syscall.Stat_t).Uid }

// resolveTrusted resolves an absolute path one component at a time,
// following each symbolic link itself (at most maxLinks), and checks
// everything the resolution passes through: every directory traversed
// (owned by a trusted user, and not writable by its group or others unless
// its sticky bit is set) and every link followed (owned by a trusted user,
// so that no one else can change where it leads), whether the link's
// target is relative or absolute. The last directory is the caller's to
// check. It returns the resolved path.
func resolveTrusted(path string, trusted trustedOwners) (string, error) {
	checkDir := func(p string, fi fs.FileInfo) error {
		if !fi.IsDir() {
			return fmt.Errorf("%s, on its path, is not a directory", p)
		}
		if u := ownerOf(p, fi); !trusted(u) {
			return fmt.Errorf("%s, on its path, is owned by uid %d, who could replace what follows", p, u)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if st.Mode&0o022 != 0 && st.Mode&syscall.S_ISVTX == 0 {
			return fmt.Errorf("%s, on its path, may be written by its group or by others without the sticky bit (mode %#o), so what follows could be replaced", p, st.Mode&0o7777)
		}
		return nil
	}
	split := func(p string) []string {
		var out []string
		for _, c := range strings.Split(p, "/") {
			if c != "" && c != "." {
				out = append(out, c)
			}
		}
		return out
	}
	cur := "/"
	fi, err := os.Lstat(cur)
	if err != nil {
		return "", err
	}
	if err := checkDir(cur, fi); err != nil {
		return "", err
	}
	rest := split(path)
	links := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		if c == ".." {
			// The parent of a directory reached this way was checked on
			// the way to it.
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if u := ownerOf(next, fi); !trusted(u) {
				return "", fmt.Errorf("the link %s, on its path, is owned by uid %d, who could change where it leads", next, u)
			}
			if links++; links > maxLinks {
				return "", fmt.Errorf("%s: more than %d symbolic links", path, maxLinks)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			rest = append(split(target), rest...)
			continue
		}
		if len(rest) > 0 {
			if err := checkDir(next, fi); err != nil {
				return "", err
			}
		} else if !fi.IsDir() {
			return "", fmt.Errorf("%s is not a directory", next)
		}
		cur = next
	}
	return cur, nil
}

func dirStat(dir string) (*syscall.Stat_t, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	return st, nil
}

func idOf(st *syscall.Stat_t) dirID { return dirID{dev: uint64(st.Dev), ino: uint64(st.Ino)} }
