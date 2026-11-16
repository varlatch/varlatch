// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package backups

import "math"

// freeSpace is not read on this platform: the check passes, and a full
// disk fails the run's write instead.
func freeSpace(string) (int64, error) { return math.MaxInt64, nil }
