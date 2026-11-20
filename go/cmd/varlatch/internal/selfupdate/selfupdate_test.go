// SPDX-License-Identifier: Apache-2.0

package selfupdate_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate/fakerelease"
	"github.com/varlatch/varlatch/go/lib/release"
)

const goos, goarch = "linux", "amd64"

func binaryOf(version string) []byte { return []byte("a varlatch binary of " + version + "\n") }

// published is a release as the release workflow publishes one: the
// platform's binary listed in SHA256SUMS, signed for the version.
func published(version string) *fakerelease.Release {
	return &fakerelease.Release{Files: map[string][]byte{
		selfupdate.Asset(version, goos, goarch):       binaryOf(version),
		selfupdate.Asset(version, "windows", "arm64"): binaryOf(version + " windows"),
		"install.sh": []byte("an installer\n"),
	}}
}

func server(t *testing.T, versions ...string) *fakerelease.Server {
	t.Helper()
	s := fakerelease.New()
	t.Cleanup(s.Close)
	for _, v := range versions {
		s.Publish(v, published(v))
	}
	return s
}

func options(current, version string) selfupdate.Options {
	return selfupdate.Options{Current: current, Version: version, GOOS: goos, GOARCH: goarch}
}

// Which release an update goes to: the newest of the Go line, a
// prerelease only from a prerelease or with --prerelease, never older
// unless asked, never a TypeScript release or a draft.
func TestChoose(t *testing.T) {
	s := server(t, "0.22.4", "0.50.0-rc.1", "0.50.0-rc.2", "0.50.0", "0.51.0-rc.1")
	s.Publish("0.52.0", &fakerelease.Release{Draft: true})
	for _, c := range []struct {
		name      string
		o         selfupdate.Options
		latest    string
		available bool
		downgrade bool
		refusal   string // a usage refusal containing this
		failure   string // another failure containing this
	}{
		{name: "rc to the newest, a prerelease", o: options("0.50.0-rc.1", ""), latest: "0.51.0-rc.1", available: true},
		{name: "a release stays on releases", o: options("0.50.0", ""), latest: "0.50.0"},
		{name: "a release to a prerelease when asked", o: func() selfupdate.Options { o := options("0.50.0", ""); o.Prerelease = true; return o }(), latest: "0.51.0-rc.1", available: true},
		{name: "newer than anything published", o: options("0.60.0", ""), latest: "0.60.0"},
		{name: "a version asked for", o: options("0.50.0-rc.1", "0.50.0-rc.2"), latest: "0.50.0-rc.2", available: true},
		{name: "with its v", o: options("0.50.0-rc.1", "v0.50.0"), latest: "0.50.0", available: true},
		{name: "the same version", o: options("0.50.0", "0.50.0"), latest: "0.50.0"},
		{name: "a prerelease from a release", o: options("0.50.0", "0.51.0-rc.1"), refusal: "pass --prerelease"},
		{name: "older", o: options("0.50.0-rc.2", "0.50.0-rc.1"), refusal: "pass --allow-downgrade"},
		{name: "older, asked", o: func() selfupdate.Options {
			o := options("0.50.0-rc.2", "0.50.0-rc.1")
			o.AllowDowngrade = true
			return o
		}(), latest: "0.50.0-rc.1", downgrade: true},
		{name: "a TypeScript release", o: options("0.50.0", "0.22.4"), refusal: "before the Go line"},
		{name: "not a version", o: options("0.50.0", "latest"), refusal: "not a release version"},
		{name: "a development build", o: options("0.50.0-dev", ""), failure: "development build"},
		{name: "a platform without binaries", o: selfupdate.Options{Current: "0.50.0", GOOS: "freebsd", GOARCH: "amd64"}, failure: "no varlatch for freebsd/amd64"},
	} {
		t.Run(c.name, func(t *testing.T) {
			plan, err := selfupdate.Choose(context.Background(), s.Source(), c.o)
			var e *selfupdate.Error
			switch {
			case c.refusal != "" || c.failure != "":
				want := c.refusal + c.failure
				if !errors.As(err, &e) || e.Usage != (c.refusal != "") || !strings.Contains(e.Message, want) {
					t.Fatalf("err %v, want %q (usage %v)", err, want, c.refusal != "")
				}
			case err != nil:
				t.Fatal(err)
			case plan.Latest != c.latest || plan.UpdateAvailable != c.available || plan.Downgrade != c.downgrade:
				t.Fatalf("plan %+v", plan)
			case plan.ReleaseURL != s.URL+"/pages/v"+c.latest:
				t.Fatalf("release URL %s", plan.ReleaseURL)
			}
		})
	}
}

func TestChooseWithoutGoReleases(t *testing.T) {
	s := server(t, "0.22.4")
	_, err := selfupdate.Choose(context.Background(), s.Source(), options("0.50.0", ""))
	if err == nil || !strings.Contains(err.Error(), "no release of the Go line") || !strings.Contains(err.Error(), "--prerelease") {
		t.Fatalf("err %v", err)
	}
}

func plan(s *fakerelease.Server, version string) selfupdate.Plan {
	return selfupdate.Plan{Current: "0.50.0-rc.1", Latest: version, UpdateAvailable: true, ReleaseURL: s.URL + "/pages/v" + version}
}

// The binary only after the signature: a release whose signature does not
// verify, for any reason, is refused before its binary is even requested.
func TestFetchVerifiesTheSignatureFirst(t *testing.T) {
	const v = "0.50.0-rc.2"
	asset := selfupdate.Asset(v, goos, goarch)
	for name, change := range map[string]func(*fakerelease.Release){
		"SHA256SUMS changed after signing": func(r *fakerelease.Release) {
			r.SumsAfterSigning = func(b []byte) []byte { return bytes.Replace(b, []byte("  install.sh"), []byte("  other.sh"), 1) }
		},
		"signed for another release": func(r *fakerelease.Release) { r.Identity = release.Identity("0.50.0-rc.1") },
		"signed by another workflow": func(r *fakerelease.Release) {
			r.Identity = "https://github.com/" + release.Repository + "/.github/workflows/other.yml@refs/tags/v" + v
		},
		"signed for another repository": func(r *fakerelease.Release) {
			r.Identity = "https://github.com/someone/varlatch/.github/workflows/release.yml@refs/tags/v" + v
		},
		"signed through another issuer": func(r *fakerelease.Release) { r.Issuer = "https://issuer.example.invalid" },
		"no signature":                  func(r *fakerelease.Release) { r.NoSignature = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := server(t)
			r := published(v)
			change(r)
			s.Publish(v, r)
			d, err := selfupdate.Fetch(context.Background(), s.Source(), plan(s, v), goos, goarch)
			if err == nil || d != nil || !strings.Contains(err.Error(), "nothing was installed") {
				t.Fatalf("d %v, err %v", d, err)
			}
			for _, p := range s.Requests() {
				if strings.HasSuffix(p, "/"+asset) {
					t.Fatalf("the binary was requested: %q", s.Requests())
				}
			}
		})
	}
}

func TestFetch(t *testing.T) {
	const v = "0.50.0-rc.2"
	asset := selfupdate.Asset(v, goos, goarch)
	s := server(t, v)
	d, err := selfupdate.Fetch(context.Background(), s.Source(), plan(s, v), goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != v || d.Asset != asset || !bytes.Equal(d.Binary, binaryOf(v)) || d.Identity != release.Identity(v) {
		t.Fatalf("%+v", d)
	}
	// In order: the checksums, their signature, then the binary, each
	// through the redirect to storage.
	var files []string
	for _, p := range s.Requests() {
		if strings.HasPrefix(p, "/download/") {
			files = append(files, filepath.Base(p))
		}
	}
	if !slices.Equal(files, []string{"SHA256SUMS", "SHA256SUMS.sigstore.json", asset}) {
		t.Fatalf("requested %q", s.Requests())
	}
}

func TestFetchRefuses(t *testing.T) {
	const v = "0.50.0-rc.2"
	asset := selfupdate.Asset(v, goos, goarch)
	for name, c := range map[string]struct {
		change func(*fakerelease.Release, *fakerelease.Server)
		want   string
		goos   string
	}{
		"a binary that does not match": {change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.Served = map[string][]byte{asset: []byte("something else\n")}
		}, want: "does not match SHA256SUMS"},
		"a cut-off binary": {change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.Served = map[string][]byte{asset: binaryOf(v)[:5]}
		}, want: "does not match SHA256SUMS"},
		"a binary SHA256SUMS does not list": {goos: "darwin", want: "does not list varlatch-0.50.0-rc.2-darwin-amd64"},
		"a redirect to plain HTTP": {change: func(r *fakerelease.Release, s *fakerelease.Server) {
			r.Redirect = func(string) string { return "http://" + s.Host() + "/storage/" + v + "/SHA256SUMS" }
		}, want: "not HTTPS"},
		"a redirect to another host": {change: func(r *fakerelease.Release, _ *fakerelease.Server) {
			r.Redirect = func(name string) string {
				if name == asset {
					return "https://storage.example.invalid/" + name
				}
				return ""
			}
		}, want: "not a host releases come from"},
	} {
		t.Run(name, func(t *testing.T) {
			s := server(t)
			r := published(v)
			if c.change != nil {
				c.change(r, s)
			}
			s.Publish(v, r)
			platform := goos
			if c.goos != "" {
				platform = c.goos
			}
			d, err := selfupdate.Fetch(context.Background(), s.Source(), plan(s, v), platform, goarch)
			if err == nil || d != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("d %v, err %v; want %q", d, err, c.want)
			}
		})
	}
	t.Run("no such release", func(t *testing.T) {
		s := server(t)
		_, err := selfupdate.Fetch(context.Background(), s.Source(), plan(s, "0.50.0-rc.9"), goos, goarch)
		if err == nil || !strings.Contains(err.Error(), "no release 0.50.0-rc.9") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("a host that does not answer", func(t *testing.T) {
		s := server(t, v)
		src := s.Source()
		s.Close()
		_, err := selfupdate.Fetch(context.Background(), src, plan(s, v), goos, goarch)
		var e *selfupdate.Error
		if !errors.As(err, &e) || !e.Unreachable {
			t.Fatalf("err %v", err)
		}
	})
}

// A copy a package manager installed is that package manager's; a link on
// PATH is followed to the file it names.
func TestLocate(t *testing.T) {
	dir := t.TempDir()
	file := func(parts ...string) string {
		p := filepath.Join(append([]string{dir}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		path string
		kind selfupdate.Kind
	}{
		{file("bin", "varlatch"), selfupdate.KindRelease},
		{file("Cellar", "varlatch", "0.50.0", "bin", "varlatch"), selfupdate.KindHomebrew},
		{file("Microsoft", "WinGet", "Packages", "Varlatch.Varlatch_Microsoft.Winget.Source_8wekyb3d8bbwe", "varlatch.exe"), selfupdate.KindWinget},
	} {
		got, err := selfupdate.Locate(c.path)
		if err != nil || got.Kind != c.kind || (c.kind == selfupdate.KindRelease) != (got.PackageManaged() == "") {
			t.Errorf("%s: %+v, %v", c.path, got, err)
		}
	}
	if runtime.GOOS == "windows" {
		return // creating a symbolic link needs a privilege there
	}
	real := file("Cellar", "varlatch", "1", "bin", "varlatch")
	link := filepath.Join(dir, "linked-varlatch")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := selfupdate.Locate(link)
	if err != nil || got.Path != real || got.Kind != selfupdate.KindHomebrew || !strings.Contains(got.PackageManaged(), "brew upgrade varlatch") {
		t.Fatalf("%+v, %v", got, err)
	}
}
