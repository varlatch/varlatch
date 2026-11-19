// SPDX-License-Identifier: Apache-2.0

//go:build windows

package transcript

import "os/exec"

// signalStatus: Windows ends a process with an exit code, never a signal.
func signalStatus(*exec.ExitError) int { return 1 }
