// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package upgrade

import "errors"

func owned(string, string) {}

// lock: an upgrade runs on a Linux host only.
func lock(string) (func(), error) {
	return nil, errors.New("varlatch upgrade runs on the Linux host of a Go installation")
}

func freeSpace(string) (uint64, uint64, error) { return 0, 0, errors.New("not on this system") }

func upgradesDir(string) error { return nil }

func ownFile(string, string) {}

func dataLock(string) (func(), error) { return func() {}, nil }
