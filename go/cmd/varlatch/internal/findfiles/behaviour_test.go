// SPDX-License-Identifier: Apache-2.0

package findfiles

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func gitInit(t *testing.T, dir string) {
	t.Helper()
	git := exec.Command("git", "init", "-q")
	git.Dir = dir
	git.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := git.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
}

// TestNeverReadsACandidate: the walk and Git need only names, never a
// candidate's contents. Every candidate here can be neither read nor
// written (mode 000), and each is still listed with its Git state.
func TestNeverReadsACandidate(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	if runtime.GOOS == "windows" {
		t.Skip("modes are POSIX ones")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitInit(t, dir)
	for name, content := range map[string]string{".gitignore": ".env\n", ".env": "A=1\n", ".env.local": "B=2\n", "id.key": "k\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", ".env.local", "id.key"} {
		if err := os.Chmod(filepath.Join(dir, name), 0); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Find(envMap{"HOME": t.TempDir()}, ".", dir, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{".env": Ignored, ".env.local": NotIgnored, "id.key": NotIgnored}
	if len(report.Files) != len(want) {
		t.Fatalf("files %+v", report.Files)
	}
	for _, f := range report.Files {
		if want[f.Path] != f.Git {
			t.Errorf("%s: %s (%s), want %s", f.Path, f.Git, f.GitError, want[f.Path])
		}
	}
}

// timed is one run of f, after a garbage collection and with the
// collector off while it runs: a collection's pause landing in one run and
// not the other is the noise that made a linear shape look 26 times slower
// at eight times the size once (macOS CI, 2026-11-20).
func timed(f func()) time.Duration {
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	began := time.Now()
	f()
	return time.Since(began)
}

// interleaved times small and large five times each, alternately, each by
// timed, after one untimed run of small, and gives the fastest of each.
func interleaved(small, large func()) (time.Duration, time.Duration) {
	small()
	var s, l time.Duration
	for i := range 5 {
		ts, tl := timed(small), timed(large)
		if i == 0 || ts < s {
			s = ts
		}
		if i == 0 || tl < l {
			l = tl
		}
	}
	return s, l
}

// growsLinearly is the timing tests' criterion (as internal/agents'):
// eight times the input in at most 24 times the time, plus 20 ms.
func growsLinearly(small, large time.Duration) bool {
	return large <= 24*small+20*time.Millisecond
}

// TestFindIsLinear: a tree eight times as large (directories, files, and
// the candidates among them, in one repository) takes time linear in its
// size: the walk, the grouping and the one Git command alike. No absolute
// time bound.
func TestFindIsLinear(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	if runtime.GOOS == "windows" {
		t.Skip("making 100,000 files there takes minutes; the walk is the same code")
	}
	tree := func(dirs int) string {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		gitInit(t, dir)
		if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for d := range dirs {
			sub := filepath.Join(dir, fmt.Sprintf("d%05d", d))
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{".env", "id.key", "a.ts", "b.ts", "c.md"} {
				if err := os.WriteFile(filepath.Join(sub, name), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		return dir
	}
	run := func(dir string) func() {
		return func() {
			report, err := Find(envMap{"HOME": t.TempDir()}, ".", dir, DefaultLimits)
			if err != nil || len(report.Files) == 0 {
				t.Fatalf("%v %v", report, err)
			}
		}
	}
	n := 2500 // a smaller run of some 50 ms; the larger tree, 100,000 entries, inside the entry bound
	small, large := interleaved(run(tree(n)), run(tree(8*n)))
	t.Logf("%d directories %v, %d directories %v (%.1fx)", n, small, 8*n, large, float64(large)/float64(small))
	if !growsLinearly(small, large) {
		t.Errorf("%d directories %v, %d directories %v: not linear", n, small, 8*n, large)
	}
}
