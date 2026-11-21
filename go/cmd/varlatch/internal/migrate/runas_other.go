// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package migrate

import (
	"errors"
	"io/fs"
	"os/exec"
)

// runAs is not built here: a migration runs on a Linux host.
func runAs(*exec.Cmd, Owner) error {
	return errors.New("running as another user is built for Linux hosts only")
}

// ownerOf is unknown here.
func ownerOf(fs.FileInfo) (uint32, uint32, bool) { return 0, 0, false }
