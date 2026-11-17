// SPDX-License-Identifier: Apache-2.0

//go:build windows

package apiclient

import "syscall"

// errnoCode is the code exitCodes.ts names for a Winsock error, as libuv
// maps it (WSAECONNREFUSED is ECONNREFUSED, and so on).
func errnoCode(errno syscall.Errno) (string, bool) {
	switch errno {
	case 10061: // WSAECONNREFUSED
		return "ECONNREFUSED", true
	case 10054: // WSAECONNRESET
		return "ECONNRESET", true
	case 10060: // WSAETIMEDOUT
		return "ETIMEDOUT", true
	case 10065: // WSAEHOSTUNREACH
		return "EHOSTUNREACH", true
	case 10051: // WSAENETUNREACH
		return "ENETUNREACH", true
	}
	return "", false
}
