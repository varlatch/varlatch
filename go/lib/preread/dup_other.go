// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package preread

import "os"

// dup opens the file again: no process changes its user here.
func dup(f *os.File) (*os.File, error) { return os.Open(f.Name()) }
