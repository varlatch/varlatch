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
