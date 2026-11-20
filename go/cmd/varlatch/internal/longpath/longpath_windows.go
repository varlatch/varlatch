// SPDX-License-Identifier: Apache-2.0

package longpath

import (
	"path/filepath"
	"strings"
)

// Of is path as CreateFile takes a path of any length: a long
// absolute one with the `\\?\` prefix (`\\?\UNC\` for a share), which
// turns off the 260-character limit, as the os package does for its own
// calls (fixLongPath); syscall.CreateFile adds nothing. A short path, one
// that has a prefix already, or one that cannot be made absolute is given
// as it is.
func Of(path string) string {
	// The os package's threshold: a directory's path may not exceed
	// MAX_PATH less 12 (an 8.3 file name), whatever the file's own name.
	const short = 248
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return path
	}
	// The length that counts is the full path's: a short relative path in
	// a deep working directory is a long one.
	abs, err := filepath.Abs(path) // cleaned, with backslashes, as the prefix needs
	if err != nil || len(abs) < short {
		return path
	}
	if strings.HasPrefix(abs, `\\`) {
		return `\\?\UNC\` + abs[2:]
	}
	return `\\?\` + abs
}
