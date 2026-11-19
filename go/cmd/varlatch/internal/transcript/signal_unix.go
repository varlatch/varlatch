// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package transcript

import (
	"os/exec"
	"syscall"
)

// signalStatus is 128 plus the signal that ended the process.
func signalStatus(exit *exec.ExitError) int {
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}
