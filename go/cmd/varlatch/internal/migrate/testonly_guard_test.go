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
	"slices"
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

// releasePlatforms are the platforms go/release/build-assets.sh builds.
var releasePlatforms = [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}}

// builtWithout reports the release platform src is built on when neither
// test tag is set ("" when none): its //go:build constraint evaluated for
// each platform the release ships, with the release tags (go1.N) true and
// cgo false (CGO_ENABLED=0), as go build evaluates it there.
func builtWithout(t *testing.T, src []byte) string {
	t.Helper()
	var expr constraint.Expr
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "package ") {
			break
		}
		if constraint.IsGoBuild(line) {
			e, err := constraint.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			expr = e
			break
		}
	}
	for _, p := range releasePlatforms {
		if expr == nil {
			return p[0] + "/" + p[1]
		}
		if expr.Eval(func(tag string) bool {
			return tag == p[0] || tag == p[1] || (tag == "unix" && p[0] != "windows") || strings.HasPrefix(tag, "go1.")
		}) {
			return p[0] + "/" + p[1]
		}
	}
	return ""
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
			if !bytes.Contains(src, []byte(v)) {
				continue
			}
			if on := builtWithout(t, src); on != "" {
				t.Errorf("%s names %s and is built without the crashpoint or rehearsal tag (on %s)", path, v, on)
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

// releasePaths are the files the release is built from; each must exist
// (a rename must update the guard, not drop out of it).
var releasePaths = []string{".github/workflows/release.yml", "go/release/build-assets.sh", "go/release/check-assets.sh", "go/image/build.sh", "go/image/Dockerfile"}

// isGuardedScript reports whether relSlash (forward-slash path relative to
// repo root) is a builder or helper script that must never build with a test
// tag: .sh and .mjs scripts at repo root, or under go/, infra/, or scripts/.
func isGuardedScript(relSlash string) bool {
	if !strings.HasSuffix(relSlash, ".sh") && !strings.HasSuffix(relSlash, ".mjs") {
		return false
	}
	if !strings.Contains(relSlash, "/") {
		return true
	}
	return strings.HasPrefix(relSlash, "go/") ||
		strings.HasPrefix(relSlash, "infra/") ||
		strings.HasPrefix(relSlash, "scripts/")
}

func TestNoReleasePathBuildsWithATestTag(t *testing.T) {
	root := repoRoot(t)
	for _, p := range releasePaths {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("the release path %s: %v (renamed? update releasePaths)", p, err)
		}
	}
	// Every Dockerfile, workflow (go.yml apart, below) and builder script at
	// repo root or under go/, infra/, or scripts/, except the rehearsal
	// harness's own (go/test/rehearsal, which builds with the tag on purpose
	// and ships nothing).
	paths := slices.Clone(releasePaths)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		relSlash := filepath.ToSlash(rel)
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git" || relSlash == "go/test/rehearsal") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		dockerfile := d.Name() == "Dockerfile" || strings.HasSuffix(d.Name(), ".Dockerfile")
		workflow := filepath.ToSlash(filepath.Dir(rel)) == ".github/workflows" && strings.HasSuffix(d.Name(), ".yml") && d.Name() != "go.yml"
		script := isGuardedScript(relSlash)
		if (dockerfile || workflow || script) && !slices.Contains(paths, relSlash) {
			paths = append(paths, relSlash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
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

func TestGuardScriptDiscoveryScope(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"build.sh", true},
		{"release.mjs", true},
		{"go/release/build-assets.sh", true},
		{"infra/release/build-release-artifacts.mjs", true},
		{"infra/host-backup/run.sh", true},
		{"scripts/verify.sh", true},
		{"scripts/conformance/run.mjs", true},
		{"apps/web/build.sh", false},
		{"README.md", false},
	}
	for _, tc := range cases {
		if got := isGuardedScript(tc.rel); got != tc.want {
			t.Errorf("isGuardedScript(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}

// A build without tags, the release's (its flags, for linux, windows and
// darwin), holds neither variable's name; the rehearsal build holds both
// (the control).
func TestTheDefaultBinaryHasNoOverrides(t *testing.T) {
	if testing.Short() {
		t.Skip("builds varlatch four times")
	}
	gomod := filepath.Join(repoRoot(t), "go")
	dir := t.TempDir()
	build := func(out, goos, goarch string, tags ...string) []byte {
		args := []string{"build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid=", "-o", filepath.Join(dir, out)}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		cmd := exec.Command("go", append(args, "./cmd/varlatch")...)
		cmd.Dir = gomod
		cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, b)
		}
		bin, err := os.ReadFile(filepath.Join(dir, out))
		if err != nil {
			t.Fatal(err)
		}
		return bin
	}
	rehearsal := build("varlatch-rehearsal", runtime.GOOS, runtime.GOARCH, "rehearsal")
	for _, v := range overrideVariables {
		if !bytes.Contains(rehearsal, []byte(v)) {
			t.Errorf("the rehearsal build does not contain %s: the control does not see the override", v)
		}
	}
	for _, p := range [][2]string{{"linux", "amd64"}, {"windows", "amd64"}, {"darwin", "arm64"}} {
		release := build("varlatch-"+p[0]+"-"+p[1], p[0], p[1])
		for _, v := range overrideVariables {
			if bytes.Contains(release, []byte(v)) {
				t.Errorf("the %s/%s build without tags contains %s", p[0], p[1], v)
			}
		}
	}
}
