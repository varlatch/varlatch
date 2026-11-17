// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agents

import "io/fs"

// linkCount is how many names a file has; on Windows the CLI treats every
// file as having one.
func linkCount(fs.FileInfo) uint64 { return 1 }
