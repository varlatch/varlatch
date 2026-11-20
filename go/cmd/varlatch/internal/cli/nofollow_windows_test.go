// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenNoFollowLongPaths: the no-follow open (import --delete-source,
// guided init's deletion, types' write check) reads a file whose path is
// longer than MAX_PATH, as the os package's own calls do.
func TestOpenNoFollowLongPaths(t *testing.T) {
	long := t.TempDir()
	for len(long) < 320 {
		long = filepath.Join(long, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(long, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(long, ".env")
	if err := os.WriteFile(file, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, given := range []string{file, strings.ReplaceAll(file, `\`, "/")} {
		f, err := openNoFollow(given)
		if err != nil {
			t.Fatalf("%d characters: %v", len(given), err)
		}
		b, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil || string(b) != "A=1\n" {
			t.Fatalf("read %q, %v", b, err)
		}
	}
}
