// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package transcript

import "os/exec"

// onTerminal: no pseudo-terminal here, so a terminal case is not replayed.
func onTerminal(cmd *exec.Cmd, which string) (status int, stdout, stderr, shown string, err error) {
	return 0, "", "", "", ErrUnsupported
}
