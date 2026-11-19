// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os/exec"
	"syscall"
)

// detach starts cmd detached and without a window, as Node.js's spawn with
// detached: true and windowsHide: true does, with no standard streams.
func detach(cmd *exec.Cmd) {
	const detachedProcess = 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: detachedProcess}
}
