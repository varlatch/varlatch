// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCaseDirHoldsNoValue: a case directory's name holds no digit, and none
// of the case's values overlaps it (a PORT=8080 case once ran in a
// directory whose random name held 8080, and masking the value rewrote the
// path); a base that holds a maskable value fails instead of flaking.
func TestCaseDirHoldsNoValue(t *testing.T) {
	base := t.TempDir()
	values := []string{"8080", "bc", "dev"}
	for range 200 {
		dir, err := CaseDir(base, values, nil)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(dir)
		if strings.ContainsAny(name, "0123456789") {
			t.Fatalf("%s holds a digit", name)
		}
		// Only what CaseDir adds below the base: the base is the test's
		// own temporary directory, whose random digits may hold 8080.
		rel, err := filepath.Rel(base, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range values {
			if strings.Contains(rel, v) {
				t.Fatalf("%s holds %q", rel, v)
			}
		}
	}
	if _, err := CaseDir(base, nil, []string{filepath.Base(base)}); err == nil {
		t.Error("a base that holds a maskable value gave a directory")
	}
	c := Case{Env: map[string]string{"PORT": "8080", "X": "{{server}}", "Y": "a", "TOKEN": "inherited-value"}, Stdin: "s3cr3t-stdin", Args: []string{"values", "set", "a-long-argument"}}
	got, maskable := CaseValues(c)
	for _, want := range []string{"8080", "inherited-value", "s3cr3t-stdin", "values", "set", "a-long-argument"} {
		if !slices.Contains(got, want) {
			t.Errorf("CaseValues misses %q: %q", want, got)
		}
	}
	for _, v := range got {
		if strings.Contains(v, "{{") || len(v) < 2 {
			t.Errorf("CaseValues holds %q", v)
		}
	}
	// Maskable: variables and stdin of 8 bytes or more, never arguments.
	if want := []string{"inherited-value", "s3cr3t-stdin"}; !slices.Equal(sorted(maskable), want) {
		t.Errorf("maskable %q, want %q", maskable, want)
	}
}

// TestCaseDirInAWindowsRunnersTemp: the system's part of the path is not
// the harness's. A Windows runner's temporary directory,
// C:\Users\runneradmin\AppData\Local\Temp (C:\Users\RUNNER~1\... as
// TEMP names it), holds "run" and "admin", which `help run` and
// `help admin` pass as arguments; the cases still get a directory.
func TestCaseDirInAWindowsRunnersTemp(t *testing.T) {
	for _, user := range []string{"runneradmin", "RUNNER~1"} {
		base := filepath.Join(t.TempDir(), "C", "Users", user, "AppData", "Local", "Temp")
		if err := os.MkdirAll(base, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"help", "run"}, {"help", "admin"}, {"run", "--help"}, {"agents", "guide", "run"}} {
			values, maskable := CaseValues(Case{Args: args, Env: map[string]string{"PORT": "1"}})
			for range 20 {
				dir, err := CaseDir(base, values, maskable)
				if err != nil {
					t.Fatalf("%s, %q: %v", base, args, err)
				}
				if !strings.HasPrefix(dir, mustReal(t, base)) {
					t.Fatalf("%s is not in %s", dir, base)
				}
			}
		}
		// A variable of masking length that the system's part holds still fails.
		values, maskable := CaseValues(Case{Env: map[string]string{"HOME_DIR": "AppData" + string(filepath.Separator) + "Local"}})
		if _, err := CaseDir(base, values, maskable); err == nil {
			t.Errorf("%s: a variable the base holds gave a directory", base)
		}
	}
}

func mustReal(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
