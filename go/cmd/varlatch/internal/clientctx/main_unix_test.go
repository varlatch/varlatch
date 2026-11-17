// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package clientctx

import (
	"os"
	"syscall"
	"testing"
)

// The vectors were recorded with the usual umask, 022: the files written
// with the default mode (local.json, its .gitignore) are 0644 there.
func TestMain(m *testing.M) {
	syscall.Umask(0o022)
	os.Exit(m.Run())
}
