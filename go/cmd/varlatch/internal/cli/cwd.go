// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"runtime"
	"syscall"
)

// Cwd is process.cwd(): the working directory as the system reports it.
// os.Getwd would prefer $PWD, which keeps the symbolic links a shell
// walked through; Node.js asks the system (libuv's getcwd), which gives
// the resolved path, so on Unix the CLI asks the system too.
func Cwd() (string, error) {
	if runtime.GOOS != "windows" {
		if dir, err := syscall.Getwd(); err == nil {
			return dir, nil
		}
	}
	return os.Getwd()
}
