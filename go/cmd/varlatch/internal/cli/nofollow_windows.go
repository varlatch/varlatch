// SPDX-License-Identifier: Apache-2.0

package cli

import "os"

// openNoFollow opens a file for reading. Windows has no O_NOFOLLOW; the
// caller compares what was opened with the Lstat it made first.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
