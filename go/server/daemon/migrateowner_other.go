// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

import "io/fs"

// statOwner is -1: no uid to keep.
func statOwner(fs.FileInfo) int { return -1 }
