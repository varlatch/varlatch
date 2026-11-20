// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package setup

import "syscall"

// noFollow refuses a symbolic link where a file is opened.
const noFollow = syscall.O_NOFOLLOW
