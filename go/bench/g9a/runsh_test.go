// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// run.sh refuses a backup destination named by one variable without the
// other (or a destinations file that is not there) before it builds or
// starts anything, so a run that names a destination never falls back to
// local archives (ADR-0059 amendment 6). varlatchd g9a checks that the
// file names the destination (the daemon's TestBenchDestinationFlags).
func TestRunShDestinationPair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("run.sh is POSIX sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	dests := filepath.Join(dir, "destinations.json")
	if err := os.WriteFile(dests, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  []string
		want string
	}{
		{[]string{"G9A_BACKUP_DESTINATION=local"}, "go together"},
		{[]string{"G9A_BACKUP_DESTINATIONS=", "G9A_BACKUP_DESTINATION=local"}, "go together"},
		{[]string{"G9A_BACKUP_DESTINATIONS=" + dests}, "go together"},
		{[]string{"G9A_BACKUP_DESTINATIONS=" + filepath.Join(dir, "missing.json"), "G9A_BACKUP_DESTINATION=local"}, "is not a file"},
	} {
		out := filepath.Join(dir, "out")
		cmd := exec.Command(sh, "run.sh", out)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "G9A_BIN=/nonexistent", "G9A_VARLATCHD=/nonexistent"}, c.env...)
		b, err := cmd.CombinedOutput()
		code := -1
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		}
		if code != 3 || !strings.Contains(string(b), c.want) {
			t.Errorf("%v: exit %d: %s", c.env, code, b)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("%v: %s was made", c.env, out)
		}
	}
}
