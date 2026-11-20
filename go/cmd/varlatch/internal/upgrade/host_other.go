// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package upgrade

import "errors"

func owned(string, string) {}

// lock: an upgrade runs on a Linux host only.
func lock(string) (func(), error) {
	return nil, errors.New("varlatch upgrade runs on the Linux host of a Go installation")
}
