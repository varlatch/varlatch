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

// TestLongPathPrefix: a long path gets the prefix (UNC for a share), a
// short one and one with a prefix already are given as they are.
func TestLongPathPrefix(t *testing.T) {
	deep := `C:\` + strings.Repeat(`dir\`, 70) + "f"
	share := `\\server\share\` + strings.Repeat(`dir\`, 70) + "f"
	for given, want := range map[string]string{
		`C:\short\f`:                       `C:\short\f`,
		deep:                               `\\?\` + deep,
		share:                              `\\?\UNC\server\share\` + strings.Repeat(`dir\`, 70) + "f",
		`\\?\` + deep:                      `\\?\` + deep,
		`\\.\C:\dev`:                       `\\.\C:\dev`,
		strings.ReplaceAll(deep, `\`, "/"): `\\?\` + deep,
	} {
		if got := longPath(given); got != want {
			t.Errorf("longPath(%q)\n got %q\nwant %q", given, got, want)
		}
	}
}
