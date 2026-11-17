// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package apiclient

import "syscall"

// errnoCode is the code exitCodes.ts names for a system error, as libuv
// names it.
func errnoCode(errno syscall.Errno) (string, bool) {
	switch errno {
	case syscall.ECONNREFUSED:
		return "ECONNREFUSED", true
	case syscall.ECONNRESET:
		return "ECONNRESET", true
	case syscall.ETIMEDOUT:
		return "ETIMEDOUT", true
	case syscall.EHOSTUNREACH:
		return "EHOSTUNREACH", true
	case syscall.ENETUNREACH:
		return "ENETUNREACH", true
	}
	return "", false
}
