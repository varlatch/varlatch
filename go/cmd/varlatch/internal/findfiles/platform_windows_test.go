// SPDX-License-Identifier: Apache-2.0

package findfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLinksOnALongPath: a file's link count is read on a path longer than
// MAX_PATH too (longpath.Of), so a hard-linked .gitignore deep in a tree
// is still seen as one and makes its repository unusual.
func TestLinksOnALongPath(t *testing.T) {
	long := t.TempDir()
	for len(long) < 320 {
		long = filepath.Join(long, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(long, 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(long, ".gitignore")
	if err := os.WriteFile(first, []byte(".env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := links(first, nil); got != 1 {
		t.Fatalf("one name: %d links", got)
	}
	if err := os.Link(first, filepath.Join(long, "second")); err != nil {
		t.Fatal(err)
	}
	if got := links(first, nil); got != 2 {
		t.Fatalf("two names: %d links", got)
	}
}
