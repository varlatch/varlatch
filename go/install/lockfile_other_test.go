// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package install

import "testing"

// lockFile is only used by the Windows end-to-end test.
func lockFile(t *testing.T, path string) {
	t.Helper()
	t.Fatalf("lockFile(%s) needs Windows", path)
}
