// SPDX-License-Identifier: AGPL-3.0-or-later

// Package servecli is varlatchd's serve_cli (ADR-0058 Decision 3; internal
// docs/design/go-step6.md, decision 12): the installation serves the Go
// CLI of its own release, for every platform, and installers that install
// it from the installation.
//
// What it serves is exactly what the release workflow signed. Before
// anything is downloaded beyond SHA256SUMS, cached or served, SHA256SUMS
// is verified against its keyless signature for the identity lib/release
// pins (the release workflow of varlatch/varlatch for this version's tag);
// every file is then checked against its line before it is written to the
// cache, and again when the cache is read at startup. Requests name files
// by an exact name in the verified set, under this version's path: no part
// of a request ever reaches the file system.
package servecli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/lib/release"
)

// Sums and Bundle are the release's checksums and their signature.
const (
	Sums   = "SHA256SUMS"
	Bundle = "SHA256SUMS.sigstore.json"
)

// Limits on what a release may send.
const (
	maxSums   = 64 << 10
	maxBundle = 1 << 20
	maxFile   = 256 << 20
)

// platforms are the CLI's, as the release builds it (go/release/build-
// assets.sh).
var platforms = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

// Installers are the scripts served at the installation's root.
var Installers = []string{"install.sh", "install.ps1"}

// Served are the release files an installation serves for version: the
// CLI for every platform and the two installers, besides SHA256SUMS and
// its signature.
func Served(version string) []string {
	var names []string
	for _, p := range platforms {
		name := "varlatch-" + version + "-" + p[0] + "-" + p[1]
		if p[0] == "windows" {
			name += ".exe"
		}
		names = append(names, name)
	}
	return append(names, Installers...)
}

// Source gives a release's files by name.
type Source interface {
	Get(ctx context.Context, name string, limit int64) ([]byte, error)
}

// GitHub is version's release on GitHub, through d (its hosts: release.
// GitHubHosts).
func GitHub(d release.Downloader, version string) Source {
	return githubSource{d: d, version: version}
}

type githubSource struct {
	d       release.Downloader
	version string
}

func (g githubSource) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	return g.d.Get(ctx, release.DownloadURL(g.version, name), limit)
}

// Release is a verified release, ready to serve.
type Release struct {
	Version string
	// Origin is the installation's address the installers name.
	Origin string
	// files are the served files by name: their path in the cache and
	// their SHA-256, as SHA256SUMS lists them.
	files map[string]served
	// scripts are the installers, stamped with Origin.
	scripts map[string][]byte
}

type served struct {
	path   string
	sha256 [sha256.Size]byte
}

// Names are the files the release serves under its version's path.
func (r *Release) Names() []string {
	names := make([]string, 0, len(r.files))
	for n := range r.files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// origin is an address an installer may name: https, or http on this
// machine, scheme and host only, nothing a script would read as anything
// but text in single quotes.
var origin = regexp.MustCompile(`^(https://[A-Za-z0-9.-]+(:[0-9]{1,5})?|https://\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?|http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?)$`)

// Options are what Prepare works with.
type Options struct {
	// Version is the release to serve: this varlatchd's.
	Version string
	// Origin is the installation's public URL's origin.
	Origin string
	// Source gives the release's files when the cache does not hold them.
	Source Source
	// Trusted is Sigstore's trusted material, fetched for each attempt.
	Trusted func(context.Context) (root.TrustedMaterial, error)
	// CacheDir holds verified releases (<CacheDir>/v<version>).
	CacheDir string
	// RetryAfter is the Manager's first wait after a failure (0: a
	// minute); it doubles up to an hour.
	RetryAfter time.Duration
}

// Prepare makes the release servable: from the cache when it holds this
// version and still verifies, otherwise from the source, verified before
// anything is written. It removes other versions from the cache.
func Prepare(ctx context.Context, o Options) (*Release, error) {
	if !release.ValidVersion(o.Version) {
		return nil, fmt.Errorf("this varlatchd's version %q is not a release version", o.Version)
	}
	if !origin.MatchString(o.Origin) {
		return nil, fmt.Errorf("public_url's origin %q is not one an installer may name", o.Origin)
	}
	trusted, err := o.Trusted(ctx)
	if err != nil {
		return nil, err
	}
	verifier, err := release.NewVerifier(trusted)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(o.CacheDir, "v"+o.Version)
	r, cacheErr := load(dir, verifier, o)
	if cacheErr != nil {
		if r, err = fetch(ctx, verifier, o); err != nil {
			return nil, err
		}
	}
	prune(o.CacheDir, "v"+o.Version)
	return r, nil
}

// verified is SHA256SUMS checked against its signature for version, and
// the names it lists among the files served.
func verified(v *release.Verifier, version string, sums, bundle []byte) (release.Sums, []string, error) {
	checked, err := v.VerifySums(version, sums, bundle)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, n := range Served(version) {
		if _, ok := checked[n]; ok {
			names = append(names, n)
		}
	}
	for _, n := range Installers {
		if !slices.Contains(names, n) {
			return nil, nil, fmt.Errorf("SHA256SUMS of %s does not list %s", version, n)
		}
	}
	if len(names) == len(Installers) {
		return nil, nil, fmt.Errorf("SHA256SUMS of %s lists no varlatch binary", version)
	}
	return checked, names, nil
}

// fetch downloads the release: SHA256SUMS and its signature, verified,
// then each file checked against its line, written to a new directory
// that replaces the cached one when everything is in it.
func fetch(ctx context.Context, v *release.Verifier, o Options) (*Release, error) {
	sums, err := o.Source.Get(ctx, Sums, maxSums)
	if err != nil {
		return nil, err
	}
	bundle, err := o.Source.Get(ctx, Bundle, maxBundle)
	if err != nil {
		return nil, err
	}
	checked, names, err := verified(v, o.Version, sums, bundle)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.CacheDir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(o.CacheDir, ".incoming-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	for _, n := range names {
		data, err := o.Source.Get(ctx, n, maxFile)
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(data) != checked[n] {
			return nil, fmt.Errorf("%s does not match SHA256SUMS of %s", n, o.Version)
		}
		if slices.Contains(Installers, n) {
			if _, err := stamp(n, data, o.Origin); err != nil {
				return nil, err
			}
		}
		if err := writeFile(filepath.Join(tmp, n), data); err != nil {
			return nil, err
		}
	}
	for n, data := range map[string][]byte{Sums: sums, Bundle: bundle} {
		if err := writeFile(filepath.Join(tmp, n), data); err != nil {
			return nil, err
		}
	}
	dir := filepath.Join(o.CacheDir, "v"+o.Version)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return nil, err
	}
	r, err := load(dir, v, o)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return r, nil
}

// load reads a cached release: its SHA256SUMS verified against its
// signature again, and every file checked against its line.
func load(dir string, v *release.Verifier, o Options) (*Release, error) {
	sums, err := readLimited(filepath.Join(dir, Sums), maxSums)
	if err != nil {
		return nil, err
	}
	bundle, err := readLimited(filepath.Join(dir, Bundle), maxBundle)
	if err != nil {
		return nil, err
	}
	checked, names, err := verified(v, o.Version, sums, bundle)
	if err != nil {
		return nil, err
	}
	r := &Release{Version: o.Version, Origin: o.Origin, files: map[string]served{}, scripts: map[string][]byte{}}
	sumsDigest, bundleDigest := sha256.Sum256(sums), sha256.Sum256(bundle)
	r.files[Sums] = served{filepath.Join(dir, Sums), sumsDigest}
	r.files[Bundle] = served{filepath.Join(dir, Bundle), bundleDigest}
	for _, n := range names {
		path := filepath.Join(dir, n)
		digest, err := hashFile(path, maxFile)
		if err != nil {
			return nil, err
		}
		if digest != checked[n] {
			return nil, fmt.Errorf("the cached %s does not match SHA256SUMS of %s", n, o.Version)
		}
		r.files[n] = served{path, checked[n]}
		if slices.Contains(Installers, n) {
			data, err := readLimited(path, maxSums)
			if err != nil {
				return nil, err
			}
			if sha256.Sum256(data) != checked[n] {
				return nil, fmt.Errorf("the cached %s changed while it was read", n)
			}
			if r.scripts[n], err = stamp(n, data, o.Origin); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

// hashFile is the SHA-256 of a regular file of at most limit bytes.
func hashFile(path string, limit int64) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	f, err := os.Open(path)
	if err != nil {
		return digest, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return digest, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return digest, fmt.Errorf("%s is not a file of at most %d bytes", path, limit)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, limit+1)); err != nil {
		return digest, err
	}
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// stamp puts the installation's origin in an installer, in the one line a
// release leaves empty for it.
func stamp(name string, script []byte, origin string) ([]byte, error) {
	var empty, filled string
	switch name {
	case "install.sh":
		empty, filled = "\nORIGIN=''\n", "\nORIGIN='"+origin+"'\n"
	case "install.ps1":
		empty, filled = "\n  $Origin = ''\n", "\n  $Origin = '"+origin+"'\n"
	default:
		return nil, fmt.Errorf("%s is not an installer", name)
	}
	// Either line ending: install.ps1 may have CRLF.
	for _, eol := range []string{"\n", "\r\n"} {
		e, f := strings.ReplaceAll(empty, "\n", eol), strings.ReplaceAll(filled, "\n", eol)
		if n := bytes.Count(script, []byte(e)); n == 1 {
			return bytes.Replace(script, []byte(e), []byte(f), 1), nil
		}
	}
	return nil, fmt.Errorf("%s has no single line for the installation's address", name)
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("%s is not a file of at most %d bytes", path, limit)
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// prune removes every cached release but keep, and any download left
// unfinished.
func prune(cacheDir, keep string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != keep {
			_ = os.RemoveAll(filepath.Join(cacheDir, e.Name()))
		}
	}
}

// hexSum is data's SHA-256 in hex, as SHA256SUMS lists it.
func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}
