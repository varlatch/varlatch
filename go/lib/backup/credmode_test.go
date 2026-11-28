// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The bucket key file's mode: the service's group may read it, nobody
// else may, and no group may write it.
func TestCredentialsModeProblem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "bucket-write.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	gid, ok := FileGID(info)
	if !ok {
		t.Fatal("no group")
	}
	for _, c := range []struct {
		mode    os.FileMode
		service int
		want    string
	}{
		{0o600, gid, ""},
		{0o400, gid, ""},
		{0o640, gid, ""},
		{0o640, -1, ""},
		{0o440, gid, ""},
		{0o640, gid + 1, "is readable by group"},
		{0o600, gid + 1, ""},
		{0o644, gid, "is open to others (mode 0644)"},
		{0o604, gid, "is open to others"},
		{0o660, gid, "may be written by its group (mode 0660)"},
		{0o620, gid, "may be written by its group"},
	} {
		if err := os.Chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		got := CredentialsModeProblem(p, info, c.service)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("mode %04o, service group %d: %q", c.mode, c.service, got)
		}
	}
	info, _ = os.Stat(dir)
	if got := CredentialsModeProblem(dir, info, gid); !strings.Contains(got, "is not a regular file") {
		t.Errorf("a directory: %q", got)
	}
}
