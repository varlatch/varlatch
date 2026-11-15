// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The data directory holds the control socket and the lock file
// (control.go). Anyone who can create or replace entries in it could put a
// socket of their own in the daemon's place, or take the lock. So serve
// refuses a directory that is not owned by the user it runs as, or that
// its group or others may write; and varlatchd admin refuses to connect
// through one, or through a socket file that is not a socket owned by the
// directory's owner. The shipped unit's directory (StateDirectoryMode=0700,
// User=varlatch) passes.

// checkServeDir is serve's check: dir must be owned by uid and writable by
// no one else.
func checkServeDir(dir string, uid int) error {
	st, err := dirStat(dir)
	if err != nil {
		return err
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("the data directory %s is owned by uid %d, not by the user varlatchd runs as (uid %d)", dir, st.Uid, uid)
	}
	return writableByOthers(dir, st)
}

// checkClientDir is varlatch admin's check before it connects or locks:
// dir writable by no one but its owner, and owned by the caller unless the
// caller is root (who runs commands for the service user). A socket that
// is there must be a socket, not a link, owned by the directory's owner.
// A directory that does not exist yet passes: the command then fails as
// it did before.
func checkClientDir(dir string, uid int) error {
	st, err := dirStat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if uid != 0 && int(st.Uid) != uid {
		return fmt.Errorf("the data directory %s is owned by uid %d, not by you (uid %d): run the command as the user varlatchd runs as", dir, st.Uid, uid)
	}
	if err := writableByOthers(dir, st); err != nil {
		return err
	}
	sock := filepath.Join(dir, ControlSocket)
	fi, err := os.Lstat(sock)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	ss, _ := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&fs.ModeSocket == 0 || ss == nil || ss.Uid != st.Uid {
		return fmt.Errorf("%s is not a socket owned by the data directory's owner: refusing to connect through it", sock)
	}
	return nil
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

func writableByOthers(dir string, st *syscall.Stat_t) error {
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("the data directory %s may be written by its group or by others (mode %#o): it holds varlatchd's control socket and lock, so it must be writable by its owner only (chmod go-w)", dir, st.Mode&0o777)
	}
	return nil
}
