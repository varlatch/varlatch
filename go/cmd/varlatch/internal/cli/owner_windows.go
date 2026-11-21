// SPDX-License-Identifier: Apache-2.0

package cli

import "os"

// fileOwner: Windows has no root (asRoot is never true there), so no owner
// is checked.
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }
