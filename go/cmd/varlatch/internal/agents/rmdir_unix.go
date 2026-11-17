// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agents

import "syscall"

// rmdir is fs.rmdirSync: it removes an empty directory, never a link.
func rmdir(path string) error { return syscall.Rmdir(path) }
