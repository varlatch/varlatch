// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// handOver, as root, gives the named files to the directory's owner, and
// follows no link nor touches a file with another name.
func TestHandOver(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changes owners, as root (go.yml's Go container)")
	}
	const uid = 65534
	base := t.TempDir()
	dir, outside := filepath.Join(base, "data"), filepath.Join(base, "outside")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{outside, filepath.Join(dir, "file"), filepath.Join(dir, "other")} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, uid, uid); err != nil {
		t.Fatal(err)
	}
	handOver(dir, "file", "link", "hard", "missing")
	for p, want := range map[string]uint32{filepath.Join(dir, "file"): uid, filepath.Join(dir, "other"): 0, outside: 0} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Sys().(*syscall.Stat_t).Uid; got != want {
			t.Errorf("%s: uid %d, want %d", p, got, want)
		}
	}
}
