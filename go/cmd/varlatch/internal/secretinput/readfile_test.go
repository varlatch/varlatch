// SPDX-License-Identifier: Apache-2.0

package secretinput

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadFileNamesNodesCode: a failed read names the code the TypeScript
// CLI's readFileSync gives, the same on every system (on Windows a
// directory fails with an error that has no POSIX code; Node says EISDIR).
func TestReadFileNamesNodesCode(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ path, want string }{
		{dir, "cannot read " + dir + " (EISDIR)"},
		{filepath.Join(dir, "missing"), "cannot read " + filepath.Join(dir, "missing") + " (ENOENT)"},
	} {
		_, err := ReadFile(c.path)
		if err == nil || err.Error() != c.want {
			t.Errorf("ReadFile(%q) = %v, want %q", c.path, err, c.want)
		}
	}
	file := filepath.Join(dir, "value")
	if err := os.WriteFile(file, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	if text, err := ReadFile(file); err != nil || text != "v" {
		t.Errorf("ReadFile = %q, %v", text, err)
	}
}
