// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/lib/release"
)

// self-update end to end (internal docs/design/go-step6.md, slice 6.7a):
// the real CLI, built for this platform with -tags selfupdatetest (the only
// build that can be pointed at another source, TestSeamIsTestOnly), replaces
// itself with another build served by a fake GitHub whose SHA256SUMS is
// signed by a test Sigstore for the release workflow's identity. The run
// after it is the new build; on Windows, that run removes the old binary
// the update renamed aside. Every refusal leaves the binary as it was, and
// nothing beside it. The same run against a real published prerelease is
// slice 6.1b's job.

const (
	fromVersion = "0.50.0-rc.1"
	toVersion   = "0.50.0-rc.2"
)

var (
	buildsOnce sync.Once
	builds     map[string][]byte
	buildsErr  error
)

// built is this package built as version with the test seam, once per run.
func built(t *testing.T, version string) []byte {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	buildsOnce.Do(func() {
		builds = map[string][]byte{}
		dir, err := os.MkdirTemp("", "varlatch-self-update-builds-")
		if err != nil {
			buildsErr = err
			return
		}
		defer os.RemoveAll(dir)
		for _, v := range []string{fromVersion, toVersion} {
			out := filepath.Join(dir, v+exeSuffix())
			cmd := exec.Command("go", "build", "-tags", "selfupdatetest", "-trimpath",
				"-ldflags", "-X github.com/varlatch/varlatch/go/lib/buildinfo.Version="+v, "-o", out, ".")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if b, err := cmd.CombinedOutput(); err != nil {
				buildsErr = &buildError{v, string(b), err}
				return
			}
			if builds[v], buildsErr = os.ReadFile(out); buildsErr != nil {
				return
			}
		}
	})
	if buildsErr != nil {
		t.Fatal(buildsErr)
	}
	return builds[version]
}

type buildError struct {
	version, output string
	err             error
}

func (e *buildError) Error() string {
	return "building " + e.version + ": " + e.err.Error() + "\n" + e.output
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// releaseOf publishes version's build as the release workflow would.
func releaseOf(t *testing.T, version string) *fakerelease.Release {
	return &fakerelease.Release{Files: map[string][]byte{
		selfupdate.Asset(version, runtime.GOOS, runtime.GOARCH): built(t, version),
		"install.sh": []byte("an installer\n"),
	}}
}

type updateRun struct {
	code     int
	out      string
	dir, exe string
}

// install puts version's build at dir/<parts...>/varlatch[.exe].
func install(t *testing.T, version string, parts ...string) (dir, exe string) {
	t.Helper()
	dir = filepath.Join(append([]string{t.TempDir()}, parts...)...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe = filepath.Join(dir, "varlatch"+exeSuffix())
	if err := os.WriteFile(exe, built(t, version), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, exe
}

// runCLI runs exe with args against s, stdin empty (not a terminal).
func runCLI(t *testing.T, s *fakerelease.Server, exe string, args ...string) updateRun {
	t.Helper()
	cfg, err := s.WriteSourceConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	home := t.TempDir()
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "VARLATCH_") && !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "XDG_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+home, "XDG_CACHE_HOME="+filepath.Join(home, ".cache"), "VARLATCH_TEST_SELFUPDATE_SOURCE="+cfg)
	out, _ := cmd.CombinedOutput()
	return updateRun{code: cmd.ProcessState.ExitCode(), out: string(out), dir: filepath.Dir(exe), exe: exe}
}

// entries is what is in dir, by name.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

func TestSelfUpdateReplacesItself(t *testing.T) {
	s := fakerelease.New()
	defer s.Close()
	s.Publish(fromVersion, releaseOf(t, fromVersion))
	s.Publish(toVersion, releaseOf(t, toVersion))
	s.Publish("0.22.4", &fakerelease.Release{Files: map[string][]byte{"varlatch-cli-0.22.4.cjs": []byte("x")}})
	_, exe := install(t, fromVersion)

	check := runCLI(t, s, exe, "self-update", "--check", "--json")
	resolved, _ := filepath.EvalSymlinks(exe)
	for _, want := range []string{`"current": "` + fromVersion + `"`, `"latest": "` + toVersion + `"`, `"updateAvailable": true`, `"install": "release"`, `"releaseUrl": "` + s.URL + "/pages/v" + toVersion + `"`} {
		if check.code != 0 || !strings.Contains(check.out, want) {
			t.Fatalf("--check --json: exit %d, no %q in\n%s", check.code, want, check.out)
		}
	}
	if !strings.Contains(check.out, strings.ReplaceAll(resolved, `\`, `\\`)) {
		t.Fatalf("--check --json names another path than %s:\n%s", resolved, check.out)
	}

	res := runCLI(t, s, exe, "self-update", "--yes")
	if res.code != 0 {
		t.Fatalf("exit %d:\n%s", res.code, res.out)
	}
	for _, want := range []string{
		"varlatch " + fromVersion + " -> " + toVersion,
		"checksum:  ok (SHA256SUMS)",
		"signature: verified (" + release.Identity(toVersion) + ")",
		"Installed varlatch " + toVersion + " at " + resolved + ".",
	} {
		if !strings.Contains(res.out, want) {
			t.Fatalf("no %q in\n%s", want, res.out)
		}
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, built(t, toVersion)) {
		t.Fatal("the file is not the new build")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
			t.Fatalf("mode %v", fi.Mode())
		}
	}

	// The next run is the new build; on Windows it removes the old binary
	// the update renamed aside while it ran.
	version := runCLI(t, s, exe, "--version")
	if version.code != 0 || !strings.HasPrefix(version.out, "varlatch "+toVersion+"\n") {
		t.Fatalf("--version after the update: exit %d, %q", version.code, version.out)
	}
	if got := entries(t, res.dir); !slices.Equal(got, []string{filepath.Base(exe)}) {
		t.Fatalf("beside the binary after the next run: %q", got)
	}
	again := runCLI(t, s, exe, "self-update", "--yes")
	if again.code != 0 || !strings.Contains(again.out, "varlatch "+toVersion+" is up to date.") {
		t.Fatalf("a second update: exit %d\n%s", again.code, again.out)
	}

	// Back to the older build, only when asked.
	refused := runCLI(t, s, exe, "self-update", fromVersion, "--yes")
	if refused.code != 64 || !strings.Contains(refused.out, "pass --allow-downgrade") {
		t.Fatalf("a downgrade: exit %d\n%s", refused.code, refused.out)
	}
	back := runCLI(t, s, exe, "self-update", fromVersion, "--allow-downgrade", "--yes")
	if got, _ := os.ReadFile(exe); back.code != 0 || !bytes.Equal(got, built(t, fromVersion)) {
		t.Fatalf("an asked downgrade: exit %d\n%s", back.code, back.out)
	}
}

func TestSelfUpdateRefuses(t *testing.T) {
	asset := selfupdate.Asset(toVersion, runtime.GOOS, runtime.GOARCH)
	for _, c := range []struct {
		name   string
		change func(*fakerelease.Release, *fakerelease.Server)
		at     []string // where the binary is, below a temporary directory
		args   []string
		code   int
		want   string
	}{
		{name: "a signature that does not verify", change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.SumsAfterSigning = func(b []byte) []byte { return bytes.Replace(b, []byte("  install.sh"), []byte("  other.sh"), 1) }
		}, code: 1, want: "does NOT verify as the release workflow of varlatch/varlatch for the tag v" + toVersion},
		{name: "another identity", change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.Identity = "https://github.com/" + release.Repository + "/.github/workflows/other.yml@refs/tags/v" + toVersion
		}, code: 1, want: "does NOT verify"},
		{name: "a binary that does not match", change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.Served = map[string][]byte{asset: []byte("something else")}
		}, code: 1, want: "does not match SHA256SUMS"},
		{name: "a redirect to another host", change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.Redirect = func(name string) string {
				if name == asset {
					return "https://storage.example.invalid/" + name
				}
				return ""
			}
		}, code: 1, want: "not a host releases come from"},
		{name: "a Homebrew install", at: []string{"Cellar", "varlatch", fromVersion, "bin"}, code: 1, want: "brew upgrade varlatch"},
		{name: "a winget install", at: []string{"WinGet", "Packages", "Varlatch.Varlatch"}, code: 1, want: "winget upgrade varlatch"},
		{name: "a TypeScript release", args: []string{"0.22.4"}, code: 64, want: "before the Go line"},
		{name: "another repository", args: []string{"--repo", "someone/varlatch"}, code: 64, want: "releases come from varlatch/varlatch only"},
		{name: "no terminal and no --yes", args: []string{}, code: 1, want: "pass --yes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := fakerelease.New()
			defer s.Close()
			r := releaseOf(t, toVersion)
			if c.change != nil {
				c.change(r, s)
			}
			s.Publish(toVersion, r)
			dir, exe := install(t, fromVersion, c.at...)
			args := c.args
			if args == nil {
				args = []string{"--yes"}
			}
			res := runCLI(t, s, exe, append([]string{"self-update"}, args...)...)
			if res.code != c.code || !strings.Contains(res.out, c.want) {
				t.Fatalf("exit %d, want %d and %q:\n%s", res.code, c.code, c.want, res.out)
			}
			if !strings.Contains(res.out, "Nothing was installed") && !strings.Contains(res.out, "nothing was installed") && c.code != 64 && !strings.Contains(c.want, "upgrade") {
				t.Fatalf("does not say nothing was installed:\n%s", res.out)
			}
			if got, _ := os.ReadFile(exe); !bytes.Equal(got, built(t, fromVersion)) {
				t.Fatal("the binary changed")
			}
			if got := entries(t, dir); !slices.Equal(got, []string{filepath.Base(exe)}) {
				t.Fatalf("beside the binary: %q", got)
			}
		})
	}
}

// Only a build with -tags selfupdatetest can be pointed at another source:
// the seam is in a file with that build tag alone, nothing else names its
// variable, and the release build passes no tags.
func TestSeamIsTestOnly(t *testing.T) {
	seam, err := os.ReadFile("internal/cli/selfupdate_testseam.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(seam, []byte("\n//go:build selfupdatetest\n")) {
		t.Fatal("selfupdate_testseam.go is not built only with -tags selfupdatetest")
	}
	const variable = "VARLATCH_TEST_SELFUPDATE_SOURCE"
	for _, dir := range []string{"internal/cli", "internal/selfupdate", "."} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || strings.HasSuffix(f, "selfupdate_testseam.go") {
				continue
			}
			if b, _ := os.ReadFile(f); bytes.Contains(b, []byte(variable)) || bytes.Contains(b, []byte("selfupdatetest")) {
				t.Errorf("%s names the test seam", f)
			}
		}
	}
	script, err := os.ReadFile("../../release/build-assets.sh")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(script, []byte("-tags")) {
		t.Fatal("build-assets.sh builds with tags")
	}
}
