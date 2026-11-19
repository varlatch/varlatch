// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/contract"
)

// servedRevision is a revision answer of the server's shape for items
// (lib/contract's JSON), with its content hash.
func servedRevision(t *testing.T, items string) string {
	t.Helper()
	text := `{"schemaVersion": 1, "semanticsVersion": 2, "items": ` + items + `}`
	parsed, err := contract.ParseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	c, err := contract.Normalize(parsed, contract.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return `{"id": "rev_` + strings.Repeat("q", 26) + `", "contentHash": "` + c.Hash() + `", "semanticsVersion": 2, "active": true, "contract": ` + string(c.Bytes()) + `}`
}

const portItem = `[{"name": "PORT", "required": {"kind": "never"}, "sensitive": false, "type": "number"}]`
const hostItem = `[{"name": "HOST", "required": {"kind": "never"}, "sensitive": false, "type": "string"}]`

// TestTypesNeverWritesThroughALink: a symbolic link at --out is refused,
// writing and checking alike, and what it points to is untouched (C-T2).
func TestTypesNeverWritesThroughALink(t *testing.T) {
	for _, check := range []bool{false, true} {
		s := newValuesServer(t)
		s.answer("GET", contractPath, 200, servedRevision(t, portItem))
		var target string
		args := []string{"types", "--out", "config.ts"}
		if check {
			args = append(args, "--check")
		}
		code, stdout, stderr := runInWith(t, s, nil, func(repo string) {
			target = filepath.Join(filepath.Dir(repo), "elsewhere.ts")
			if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(repo, "config.ts")); err != nil {
				t.Skipf("no symbolic links here: %v", err)
			}
		}, args...)
		if code != ExitFailure || stdout != "" || !strings.Contains(stderr, "is a symbolic link; varlatch types never writes through one, so point --out at the file itself. Nothing was written.") {
			t.Errorf("--check %v: status %d, %q %q", check, code, stdout, stderr)
		}
		if b, _ := os.ReadFile(target); string(b) != "original" {
			t.Errorf("the link's target was written: %q", b)
		}
		entries, _ := os.ReadDir(".")
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("a temporary file was left: %s", e.Name())
			}
		}
	}
}

// TestTypesKeepsTheFilesMode: a rewritten module keeps the old file's mode
// (0600, and none at all), and no temporary file is left beside it.
func TestTypesKeepsTheFilesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	for _, mode := range []os.FileMode{0o600, 0o640, 0} {
		s := newValuesServer(t)
		s.answer("GET", contractPath, 200, servedRevision(t, hostItem))
		code, stdout, stderr := runInWith(t, s, map[string]string{"src/config.ts": "stale\n"}, func(repo string) {
			if err := os.Chmod(filepath.Join(repo, "src", "config.ts"), mode); err != nil {
				t.Fatal(err)
			}
		}, "types", "--out", "src/config.ts")
		if code != ExitOK || !strings.HasPrefix(stdout, "Wrote src/config.ts from Contract Revision rev_") || stderr != "" {
			t.Fatalf("mode %o: status %d, %q %q", mode, code, stdout, stderr)
		}
		info, err := os.Stat(filepath.Join("src", "config.ts"))
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("mode %o became %v (%v)", mode, info.Mode().Perm(), err)
		}
		_ = os.Chmod(filepath.Join("src", "config.ts"), 0o600)
		b, _ := os.ReadFile(filepath.Join("src", "config.ts"))
		if !strings.Contains(string(b), "readonly HOST?: string;") {
			t.Errorf("not rewritten: %.200q", b)
		}
		entries, _ := os.ReadDir("src")
		if len(entries) != 1 {
			t.Errorf("src holds %d entries, want the module only", len(entries))
		}
	}
}

// TestNodeExtname: path.extname's answers, the cases --out depends on.
func TestNodeExtname(t *testing.T) {
	for path, want := range map[string]string{
		"/a/config.ts": ".ts", "/a/config.d.ts": ".ts", "/a/.ts": "", "/a/..ts": ".ts", "/a/...": ".",
		"/a/..": "", "/a/config.": ".", "/a/config": "", "/a.b/config": "", "/a/config.__proto__": ".__proto__",
		"/a/x.py": ".py", "/a/.x.py": ".py", "/a/x.PY": ".PY",
	} {
		if got := nodeExtname(path); got != want {
			t.Errorf("nodeExtname(%q) = %q, want %q", path, got, want)
		}
	}
}
