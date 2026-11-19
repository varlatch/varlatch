// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCaseDirHoldsNoValue: a case directory's name holds no digit, and its
// path none of the case's values (a PORT=8080 case once ran in a directory
// whose random name held 8080, and masking the value rewrote the path); a
// base that holds a value fails instead of flaking.
func TestCaseDirHoldsNoValue(t *testing.T) {
	base := t.TempDir()
	values := []string{"8080", "bc", "dev"}
	for range 200 {
		dir, err := CaseDir(base, values)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(dir)
		if strings.ContainsAny(name, "0123456789") {
			t.Fatalf("%s holds a digit", name)
		}
		for _, v := range values {
			if strings.Contains(dir, v) {
				t.Fatalf("%s holds %q", dir, v)
			}
		}
	}
	if _, err := CaseDir(base, []string{filepath.Base(base)}); err == nil {
		t.Error("a base that holds a value gave a directory")
	}
	c := Case{Env: map[string]string{"PORT": "8080", "X": "{{server}}", "Y": "a"}, Stdin: "s3cr3t", Args: []string{"values", "set"}}
	got := CaseValues(c)
	for _, want := range []string{"8080", "s3cr3t", "values", "set"} {
		if !strings.Contains(strings.Join(got, "\n"), want) {
			t.Errorf("CaseValues misses %q: %q", want, got)
		}
	}
	for _, v := range got {
		if strings.Contains(v, "{{") || len(v) < 2 {
			t.Errorf("CaseValues holds %q", v)
		}
	}
}
