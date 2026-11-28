// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package backup

import "io/fs"

// FileGID: no Unix modes here; nothing is judged.
func FileGID(fs.FileInfo) (int, bool) { return 0, false }
