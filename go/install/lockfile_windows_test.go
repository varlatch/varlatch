// SPDX-License-Identifier: Apache-2.0

package install

import (
	"syscall"
	"testing"
)

// lockFile holds path open until the test ends the way a running program
// holds its own executable: others may read it, but not write, replace or
// delete it.
func lockFile(t *testing.T, path string) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("locking %s: %v", path, err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(h) })
}
