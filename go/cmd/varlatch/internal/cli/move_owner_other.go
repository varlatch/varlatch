// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cli

import "os"

// keepOwner: a Go installation runs on Linux; nothing to keep elsewhere.
func keepOwner(*os.File, os.FileInfo) {}
