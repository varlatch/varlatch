// SPDX-License-Identifier: Apache-2.0

//go:build unix

package migrate

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
)

// runAs runs cmd as o, with no supplementary groups; as it is when this
// process is o already.
func runAs(cmd *exec.Cmd, o Owner) error {
	if int(o.UID) == os.Getuid() && int(o.GID) == os.Getgid() {
		return nil
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: o.UID, Gid: o.GID, Groups: []uint32{}}}
	return nil
}

// giveDir gives the directory path, which this process made, to o: through
// its own descriptor, and last, since o may then change what is in it.
func giveDir(path string, o Owner) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if uid, _, ok := ownerOf(st); !ok || int(uid) != os.Geteuid() {
		return fmt.Errorf("%s is not the directory that was made there", path)
	}
	return give(f, o)
}

// ownerOf is a file's owner.
func ownerOf(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return s.Uid, s.Gid, true
}
