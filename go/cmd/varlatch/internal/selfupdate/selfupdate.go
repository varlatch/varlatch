// SPDX-License-Identifier: Apache-2.0

// Package selfupdate replaces the running varlatch with a release's
// (internal docs/design/go-step6.md, slice 6.7a, decision 11). It trusts
// what the installers trust (ADR-0059 Decision 8), in the same order:
//
//  1. SHA256SUMS and its keyless signature, SHA256SUMS.sigstore.json, are
//     downloaded from the release, over HTTPS, from GitHub's hosts only
//     (redirects included), and kept in memory;
//  2. the signature is verified (lib/release: Sigstore's trusted root,
//     fetched through its TUF repository) for the identity lib/release
//     pins, the release workflow of varlatch/varlatch for that version's
//     tag; nothing is downloaded or written before it verifies;
//  3. the platform's binary is downloaded, in memory, and checked against
//     its line in SHA256SUMS;
//  4. only then is it written: a new file in the target's own directory,
//     made executable, run once to report its version, then renamed over
//     the target, so the target is always one whole binary. On Windows the
//     running file is renamed aside first, and removed by the next run
//     (CleanUp).
//
// It never goes to an older release unless asked (AllowDowngrade), to a
// prerelease unless this binary is one or it is asked (Prerelease), or to a
// release before the Go line (0.50.0), and it leaves a copy a package
// manager installed to that package manager.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/lib/release"
)

// FirstGoRelease is the first release of the Go line: releases before it
// have no native binaries. Its prereleases (0.50.0-rc.N) are the Go line's
// too: goLineFloor, the lowest version Semantic Versioning orders at or
// after 0.50.0's prereleases, is the bound.
const (
	FirstGoRelease = "0.50.0"
	goLineFloor    = "0.50.0-0"
)

// Limits on what a release may send.
const (
	maxSums    = 64 << 10
	maxBundle  = 1 << 20
	maxListing = 8 << 20
	maxBinary  = 256 << 20
)

// Source is where releases come from and what verifies them.
type Source struct {
	// API is the repository's REST API base, Download the base of its
	// release files (<Download>/v<version>/<file>), Pages the base of a
	// release's page (<Pages>/v<version>).
	API, Download, Pages string
	// Hosts are the only hosts a request or a redirect may reach, as
	// host[:port].
	Hosts []string
	// UserAgent is sent with every request.
	UserAgent string
	// roots verify the hosts' TLS certificates; nil is the system's.
	roots *x509.CertPool
	// Trusted is Sigstore's trusted material for the signature check.
	Trusted func(context.Context) (root.TrustedMaterial, error)
}

// GitHub is the only Source a release build uses: varlatch/varlatch's
// releases on GitHub, verified against Sigstore's live trusted root
// (cached in cacheDir, as verify-release does).
func GitHub(userAgent, cacheDir string) Source {
	return Source{
		API:      "https://api.github.com/repos/" + release.Repository,
		Download: "https://github.com/" + release.Repository + "/releases/download",
		Pages:    "https://github.com/" + release.Repository + "/releases/tag",
		// github.com redirects a release file to its storage host.
		Hosts:     []string{"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"},
		UserAgent: userAgent,
		Trusted: func(ctx context.Context) (root.TrustedMaterial, error) {
			return release.LiveTrustedRoot(ctx, cacheDir)
		},
	}
}

// WithRoots is s verifying its hosts' TLS certificates against roots.
func (s Source) WithRoots(roots *x509.CertPool) Source {
	s.roots = roots
	return s
}

// Error is an update that did not happen: Message says why and what to do;
// Unreachable when a host could not be reached (exit 69); Usage when the
// request itself is refused (exit 64).
type Error struct {
	Message     string
	Unreachable bool
	Usage       bool
}

func (e *Error) Error() string { return e.Message }

func fail(format string, a ...any) error { return &Error{Message: fmt.Sprintf(format, a...)} }

func refuse(format string, a ...any) error {
	return &Error{Message: fmt.Sprintf(format, a...), Usage: true}
}

// failed wraps err from a download into an Error.
func failed(prefix string, err error) error {
	var ue *unreachableError
	return &Error{Message: prefix + err.Error(), Unreachable: errors.As(err, &ue)}
}

// notInstalled wraps err from a release file's download into an Error
// that says nothing was installed.
func notInstalled(err error) error {
	var ue *unreachableError
	return &Error{Message: err.Error() + "; nothing was installed", Unreachable: errors.As(err, &ue)}
}

// Options is what was asked.
type Options struct {
	// Version is the release asked for, "" for the newest.
	Version string
	// Prerelease allows a prerelease when this binary is not one.
	Prerelease bool
	// AllowDowngrade allows a release older than this binary.
	AllowDowngrade bool
	// Current is this binary's version; GOOS and GOARCH its platform.
	Current, GOOS, GOARCH string
}

// Plan is the release an update goes to, as --check reports it.
type Plan struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"updateAvailable"`
	ReleaseURL      string `json:"releaseUrl"`
	// Downgrade: Latest is older than Current (asked for).
	Downgrade bool `json:"-"`
}

// Asset is the platform's binary in a release.
func Asset(version, goos, goarch string) string {
	name := "varlatch-" + version + "-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// supported is whether the release builds a binary for the platform.
func supported(goos, goarch string) bool {
	return (goos == "linux" || goos == "darwin" || goos == "windows") && (goarch == "amd64" || goarch == "arm64")
}

// Choose decides the release: the one asked for, or the newest of the Go
// line this binary may go to.
func Choose(ctx context.Context, src Source, o Options) (Plan, error) {
	if !release.ValidVersion(o.Current) || strings.HasSuffix(o.Current, "-dev") {
		return Plan{}, fail("this varlatch is a development build (%s): self-update replaces a release's binary; build the new one from source", o.Current)
	}
	if !supported(o.GOOS, o.GOARCH) {
		return Plan{}, fail("releases have no varlatch for %s/%s", o.GOOS, o.GOARCH)
	}
	onPrerelease := release.Prerelease(o.Current)
	target := strings.TrimPrefix(o.Version, "v")
	if target != "" {
		if !release.ValidVersion(target) {
			return Plan{}, refuse("not a release version: %s", o.Version)
		}
		if older(target, goLineFloor) {
			return Plan{}, refuse("%s is a release of the TypeScript CLI, before the Go line (%s): it has no native varlatch to install; install it as https://docs.varlatch.com/reference/install-the-cli/ describes", target, FirstGoRelease)
		}
		if release.Prerelease(target) && !onPrerelease && !o.Prerelease {
			return Plan{}, refuse("%s is a prerelease and this varlatch (%s) is not one: pass --prerelease to install it", target, o.Current)
		}
	} else {
		newest, err := newestRelease(ctx, src, onPrerelease || o.Prerelease)
		if err != nil {
			return Plan{}, err
		}
		target = newest
	}
	order, _ := release.CompareVersions(target, o.Current)
	plan := Plan{Current: o.Current, Latest: target, UpdateAvailable: order > 0, ReleaseURL: src.Pages + "/v" + target, Downgrade: order < 0}
	if plan.Downgrade && o.Version == "" {
		// The newest this binary may go to is older (a prerelease of the
		// next release, with --prerelease not given): nothing to do.
		plan.Latest, plan.ReleaseURL, plan.Downgrade = o.Current, src.Pages+"/v"+o.Current, false
	}
	if plan.Downgrade && !o.AllowDowngrade {
		return plan, refuse("%s is older than this varlatch (%s): pass --allow-downgrade to install it", target, o.Current)
	}
	return plan, nil
}

func older(a, b string) bool {
	order, _ := release.CompareVersions(a, b)
	return order < 0
}

// maxPages bounds how many pages of the release list are read.
const maxPages = 10

// newestRelease is the newest published release of the Go line, a
// prerelease only when allowed. The tag gives the version; the signature
// check binds what is installed to that tag. GitHub lists releases newest
// first by creation, not by version, in pages: the next page is read while
// the last one improved on the newest version found (or found none yet),
// at most maxPages, so a patch release created after a later minor's is
// still compared with it.
func newestRelease(ctx context.Context, src Source, prereleases bool) (string, error) {
	newest := ""
	page := src.API + "/releases?per_page=100"
	for n := 0; n < maxPages && page != ""; n++ {
		body, header, err := src.getWithHeader(ctx, page, maxListing, "application/vnd.github+json")
		if err != nil {
			return "", failed("looking up the newest release: ", err)
		}
		var listed []struct {
			Tag   string `json:"tag_name"`
			Draft bool   `json:"draft"`
		}
		if err := json.Unmarshal(body, &listed); err != nil {
			return "", fail("looking up the newest release: GitHub's answer is not a list of releases")
		}
		improved := false
		for _, r := range listed {
			v, ok := strings.CutPrefix(r.Tag, "v")
			if r.Draft || !ok || !release.ValidVersion(v) || older(v, goLineFloor) || release.Prerelease(v) && !prereleases {
				continue
			}
			if newest == "" || older(newest, v) {
				newest, improved = v, true
			}
		}
		if !improved && newest != "" {
			break
		}
		page = nextPage(header)
	}
	if newest == "" {
		if prereleases {
			return "", fail("no release of the Go line (%s or later) is published yet", FirstGoRelease)
		}
		return "", fail("no release of the Go line (%s or later) is published yet; pass --prerelease to install a prerelease", FirstGoRelease)
	}
	return newest, nil
}

// Download is a release's binary for this platform, verified.
type Download struct {
	Version, Asset string
	// Identity is the identity the signature was verified for.
	Identity string
	Binary   []byte
}

// Fetch downloads and verifies the plan's release for the platform: the
// signature on SHA256SUMS first, then the binary against it.
func Fetch(ctx context.Context, src Source, plan Plan, goos, goarch string) (*Download, error) {
	version := plan.Latest
	asset := Asset(version, goos, goarch)
	base := src.Download + "/v" + url.PathEscape(version) + "/"
	sums, err := src.get(ctx, base+"SHA256SUMS", maxSums, "")
	if errors.Is(err, errNotFound) {
		return nil, fail("no release %s with a SHA256SUMS: %s", version, plan.ReleaseURL)
	}
	if err != nil {
		return nil, notInstalled(err)
	}
	bundle, err := src.get(ctx, base+"SHA256SUMS.sigstore.json", maxBundle, "")
	if errors.Is(err, errNotFound) {
		return nil, fail("release %s has no signature (SHA256SUMS.sigstore.json); nothing was installed", version)
	}
	if err != nil {
		return nil, notInstalled(err)
	}
	trusted, err := src.Trusted(ctx)
	if err != nil {
		return nil, &Error{Message: err.Error() + "; nothing was installed", Unreachable: true}
	}
	verifier, err := release.NewVerifier(trusted)
	if err != nil {
		return nil, fail("%v", err)
	}
	checked, err := verifier.VerifySums(version, sums, bundle)
	if err != nil {
		// The identity is a URL with "@refs/tags/..." in it, which the
		// CLI's fail-safe on stderr would take for a password: the message
		// names it by its parts, and leaves out a detail that quotes one.
		detail := ""
		if text := err.Error(); !strings.Contains(text, "@") {
			detail = " (" + text + ")"
		}
		return nil, fail("the signature on SHA256SUMS does NOT verify as the release workflow of %s for the tag v%s%s; nothing was installed", release.Repository, version, detail)
	}
	want, ok := checked[asset]
	if !ok {
		return nil, fail("SHA256SUMS of %s does not list %s; nothing was installed", version, asset)
	}
	binary, err := src.get(ctx, base+url.PathEscape(asset), maxBinary, "")
	if err != nil {
		return nil, notInstalled(err)
	}
	if sha256.Sum256(binary) != want {
		return nil, fail("%s does not match SHA256SUMS; nothing was installed", asset)
	}
	return &Download{Version: version, Asset: asset, Identity: release.Identity(version), Binary: binary}, nil
}
