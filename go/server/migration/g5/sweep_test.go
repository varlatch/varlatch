// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A run killed outright (SIGKILL, go test's -timeout) cleans nothing up;
// the next run's setup removes what it left: a shared directory whose
// owner process is gone, and a directory without an owner file once it is
// older than any run. A live run's, and a fresh one's, stay.
func TestG5SweepsAbandonedDirectories(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// The short target directories' root, apart from TMPDIR, as /tmp is
	// when TMPDIR names another directory.
	short := t.TempDir()
	wasRoot := shortRoot
	shortRoot = short
	t.Cleanup(func() { shortRoot = wasRoot })
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	mkIn := func(root, name, owner string, age time.Duration) string {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Join(d, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		if owner != "" {
			if err := os.WriteFile(filepath.Join(d, ownerFile), []byte(owner), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(d, at, at); err != nil {
			t.Fatal(err)
		}
		return d
	}
	mk := func(name, owner string, age time.Duration) string { return mkIn(tmp, name, owner, age) }
	// A short target directory holds a link to its world's target, which
	// the sweep removes (the link), never what it leads to.
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	mkShort := func(name, owner string, age time.Duration) string {
		d := mkIn(short, name, owner, age)
		if err := os.Symlink(target, filepath.Join(d, "t")); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(d, at, at); err != nil {
			t.Fatal(err)
		}
		return d
	}
	shortGone := mkShort("g5s111", strconv.Itoa(dead.Process.Pid), time.Minute)
	shortLive := mkShort("g5s222", strconv.Itoa(os.Getpid()), 8*time.Hour)
	shortFresh := mkShort("g5s333", "", time.Minute)
	shortOld := mkShort("g5s444", "", 7*time.Hour)
	gone := mk("g5-interrupt-dead", strconv.Itoa(dead.Process.Pid), time.Minute)
	live := mk("g5-interrupt-live", strconv.Itoa(os.Getpid()), 8*time.Hour)
	fresh := mk("g5-interrupt-fresh", "", time.Minute)
	old := mk("g5-interrupt-old", "", 7*time.Hour)
	decide := mk("g5-decide-old", "", 7*time.Hour)
	ca := mk("g5-headscale-ca-old", "", 7*time.Hour)
	other := mk("unrelated-old", "", 7*time.Hour)
	sweepAbandoned()
	for d, kept := range map[string]bool{gone: false, live: true, fresh: true, old: false, decide: false, ca: false, other: true,
		shortGone: false, shortLive: true, shortFresh: true, shortOld: false} {
		if _, err := os.Stat(d); (err == nil) != kept {
			t.Errorf("%s: kept %v, want %v", filepath.Base(d), err == nil, kept)
		}
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the swept short directories' link target was removed: %v", err)
	}
}
