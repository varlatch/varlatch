// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package upgrade

import (
	"errors"
	"os"
	"os/exec"
)

// lock: an upgrade runs on a Linux host only.
func lock(string) (*os.File, error) {
	return nil, errors.New("varlatch upgrade runs on the Linux host of a Go installation")
}

func lockData(string) (func(), error) { return func() {}, nil }

func ownerToBe(string) (uint32, uint32, bool, error) { return 0, 0, false, nil }

func asOwner(*exec.Cmd, uint32, uint32) {}

func killSelf() { os.Exit(1) }

func rootOwned(string) error { return nil }

func freeSpace(string) (uint64, uint64, error) { return 0, 0, errors.New("not on this system") }

func openRegular(path string) (*os.File, error) { return os.Open(path) }
