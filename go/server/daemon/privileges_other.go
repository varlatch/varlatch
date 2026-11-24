// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import (
	"io"
	"os"

	"github.com/varlatch/varlatch/go/server/config"
)

func becomeOwner(*config.Config, func(), io.Writer) error { return nil }

func rootsAlone(string) bool { return false }

func rootsOnlyName(os.FileInfo) bool { return false }

func fileAndDirectory(int, int) bool { return false }

func holdsLock(string) bool { return false }

func createAlone(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
