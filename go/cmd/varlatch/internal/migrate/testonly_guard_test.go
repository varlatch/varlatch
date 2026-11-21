// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"go/build/constraint"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The test builds' overrides (testonly.go) never reach a release: only a
// file built with the crashpoint or rehearsal tag names their variables,
// no release path builds with either tag, and the binary a build without
// tags makes does not contain them.

var overrideVariables = []string{"VARLATCH_MIGRATE_PIN", "VARLATCH_MIGRATE_IMAGE_USER"}

// repoRoot is the repository's root: the directory above go/.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && filepath.Base(dir) == "go" {
			return filepath.Dir(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go/go.mod above the package")
		}
		dir = parent
	}
}

// builtWithout reports whether src is built when neither test tag is set.
func builtWithout(t *testing.T, src []byte) bool {
	t.Helper()
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "package ") {
			break
		}
		if constraint.IsGoBuild(line) {
			expr, err := constraint.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			return expr.Eval(func(tag string) bool { return tag == runtime.GOOS || tag == runtime.GOARCH || tag == "unix" })
		}
	}
	return true
}

func TestTestOverridesAreInTestBuildsOnly(t *testing.T) {
	gomod := filepath.Join(repoRoot(t), "go")
	err := filepath.WalkDir(gomod, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, v := range overrideVariables {
			if bytes.Contains(src, []byte(v)) && builtWithout(t, src) {
				t.Errorf("%s names %s and is built without the crashpoint or rehearsal tag", path, v)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// testTags is a -tags value, or a GOFLAGS one, that names a test tag.
var testTags = regexp.MustCompile(`(-tags[= ]|GOFLAGS)[^\n]*\b(crashpoint|rehearsal)\b`)

func TestNoReleasePathBuildsWithATestTag(t *testing.T) {
	root := repoRoot(t)
	paths := []string{".github/workflows/release.yml", "go/release/build-assets.sh", "go/release/check-assets.sh", "go/image/build.sh"}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && (d.Name() == "Dockerfile" || strings.HasSuffix(d.Name(), ".Dockerfile")) {
			rel, _ := filepath.Rel(root, path)
			paths = append(paths, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		src, err := os.ReadFile(filepath.Join(root, p))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if m := testTags.Find(src); m != nil {
			t.Errorf("%s builds with a test tag: %q", p, m)
		}
	}
	// go.yml tests with them (G5, G7's kills) and vets them; it builds no
	// release asset, and never runs anything with the rehearsal tag but vet.
	src, err := os.ReadFile(filepath.Join(root, ".github/workflows/go.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "rehearsal") && strings.Contains(line, "-tags") && !strings.Contains(line, "go vet -tags rehearsal ") {
			t.Errorf("go.yml uses the rehearsal tag beyond vet: %s", strings.TrimSpace(line))
		}
	}
}

// A build without tags, the release's, holds neither variable's name;
// the rehearsal build holds both (the control).
func TestTheDefaultBinaryHasNoOverrides(t *testing.T) {
	if testing.Short() {
		t.Skip("builds varlatch twice")
	}
	gomod := filepath.Join(repoRoot(t), "go")
	dir := t.TempDir()
	build := func(out string, tags ...string) []byte {
		args := []string{"build", "-trimpath", "-o", filepath.Join(dir, out)}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		cmd := exec.Command("go", append(args, "./cmd/varlatch")...)
		cmd.Dir = gomod
		cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, b)
		}
		bin, err := os.ReadFile(filepath.Join(dir, out))
		if err != nil {
			t.Fatal(err)
		}
		return bin
	}
	release, rehearsal := build("varlatch"), build("varlatch-rehearsal", "rehearsal")
	for _, v := range overrideVariables {
		if bytes.Contains(release, []byte(v)) {
			t.Errorf("the build without tags contains %s", v)
		}
		if !bytes.Contains(rehearsal, []byte(v)) {
			t.Errorf("the rehearsal build does not contain %s: the control does not see the override", v)
		}
	}
}
