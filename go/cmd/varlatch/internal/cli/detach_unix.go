// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os/exec"
	"syscall"
)

// detach starts cmd in a session of its own, as Node.js's spawn with
// detached: true does, with no standard streams (stdio: "ignore").
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
