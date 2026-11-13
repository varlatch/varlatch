// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package diskprobe

import "os"

// datasync flushes the file. On macOS Go's Sync uses F_FULLFSYNC, which,
// like SQLite's fullfsync, reaches the disk rather than its cache.
func datasync(f *os.File) error { return f.Sync() }
