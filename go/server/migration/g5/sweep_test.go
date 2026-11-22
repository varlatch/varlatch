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
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	mk := func(name, owner string, age time.Duration) string {
		d := filepath.Join(tmp, name)
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
	gone := mk("g5-interrupt-dead", strconv.Itoa(dead.Process.Pid), time.Minute)
	live := mk("g5-interrupt-live", strconv.Itoa(os.Getpid()), 8*time.Hour)
	fresh := mk("g5-interrupt-fresh", "", time.Minute)
	old := mk("g5-interrupt-old", "", 7*time.Hour)
	decide := mk("g5-decide-old", "", 7*time.Hour)
	other := mk("unrelated-old", "", 7*time.Hour)
	sweepAbandoned()
	for d, kept := range map[string]bool{gone: false, live: true, fresh: true, old: false, decide: false, other: true} {
		if _, err := os.Stat(d); (err == nil) != kept {
			t.Errorf("%s: kept %v, want %v", filepath.Base(d), err == nil, kept)
		}
	}
}
