// SPDX-License-Identifier: Apache-2.0

package install

import (
	"syscall"
	"testing"
)

// lockFile opens path with no sharing until the test ends, as a running
// program holds its own executable: it cannot be replaced or deleted.
func lockFile(t *testing.T, path string) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("locking %s: %v", path, err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(h) })
}
