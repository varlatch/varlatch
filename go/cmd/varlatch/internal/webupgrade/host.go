// SPDX-License-Identifier: Apache-2.0

//go:build unix

package webupgrade

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/varlatch/varlatch/go/lib/release"
)

// writeRootFile replaces path with data, durably (this process is root,
// so the file is root's).
func writeRootFile(path string, data []byte, mode fs.FileMode) error {
	if err := release.WriteDurably(path, data, mode); err != nil && !errors.Is(err, release.ErrNotDurable) {
		return err
	}
	return nil
}

// mkdirRoot makes a directory of root's alone, or checks that it is one.
func mkdirRoot(path string, mode fs.FileMode) error {
	if err := os.Mkdir(path, mode); err == nil {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || st.Uid != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not a directory of root's alone: remove it, or make it one (chown root: and chmod 0700)", path)
	}
	return nil
}

func systemctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unitState is a unit's ActiveState (active, activating, failed, ...) and
// Result. Not `is-active`: that answers no for a oneshot that runs, which
// is activating until it exits.
func unitState(ctx context.Context, unit string) (active, result string, err error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--property=Result", unit).Output()
	if err != nil {
		return "", "", fmt.Errorf("systemctl show %s: %v", unit, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			active = v
		case "Result":
			result = v
		}
	}
	return active, result, nil
}

// lockDir takes an exclusive lock (flock) on the directory dir, opened
// without following a link: waiting for it when wait, else ok false when
// another process holds it. The lock goes with the process, so a run that
// dies holds nothing. An error wraps fs.ErrNotExist when dir is not there.
func lockDir(dir string, wait bool) (unlock func(), ok bool, err error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, &fs.PathError{Op: "open", Path: dir, Err: err}
	}
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	for {
		err = unix.Flock(fd, how)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		_ = unix.Close(fd)
		return nil, false, nil
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, false, &fs.PathError{Op: "flock", Path: dir, Err: err}
	}
	return func() { _ = unix.Close(fd) }, true, nil
}
