// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The G5 gate's hooks are test builds' only: every Go file outside the
// tests that reads a VARLATCH_TEST_ variable, or one of the migration's
// crashpoint variables, is built with the crashpoint tag alone, and the
// release builds its binaries with no tag at all.
func TestTestHooksAreCrashpointOnly(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	hook := regexp.MustCompile(`"VARLATCH_TEST_[A-Z_]+"|"VARLATCH_MIGRATE_(PIN|PAUSE|LOG|IMAGE_USER)"`)
	tag := regexp.MustCompile(`(?m)^//go:build [^\n]*\bcrashpoint\b`)
	notTag := regexp.MustCompile(`(?m)^//go:build [^\n]*!crashpoint`)
	found := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !hook.Match(b) {
			return nil
		}
		found++
		if !tag.Match(b) || notTag.Match(b) {
			t.Errorf("%s reads a test hook's variable outside a crashpoint build", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 3 {
		t.Fatalf("found %d hook files: the scan does not see them", found)
	}
	b, err := os.ReadFile(filepath.Join(root, "release", "build-assets.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "-tags") {
		t.Error("go/release/build-assets.sh builds with tags: a release builds with none")
	}
}
