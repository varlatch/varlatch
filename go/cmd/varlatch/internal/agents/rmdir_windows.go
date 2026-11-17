// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agents

import "os"

// rmdir is fs.rmdirSync: it removes an empty directory.
func rmdir(path string) error { return os.Remove(path) }
