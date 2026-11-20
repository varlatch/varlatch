// SPDX-License-Identifier: Apache-2.0

//go:build unix

package migrate

import (
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

// ownerOf is a file's owner.
func ownerOf(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return s.Uid, s.Gid, true
}
