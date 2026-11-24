// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os/exec"
	"syscall"
)

// asServiceUser runs cmd as the service user.
func asServiceUser(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: serviceUID, Gid: serviceUID, Groups: []uint32{}}}
}
