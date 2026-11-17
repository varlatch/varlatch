// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/release"
)

// fileFlags collects repeated --file path=name options.
type fileFlags []string

func (f *fileFlags) String() string     { return strings.Join(*f, ",") }
func (f *fileFlags) Set(v string) error { *f = append(*f, v); return nil }

const verifyReleaseUsage = `usage: varlatch verify-release --version <version> --sums <SHA256SUMS> --bundle <SHA256SUMS.sigstore.json> [--file <path>=<name>]...

Checks that SHA256SUMS is signed by the release workflow of varlatch/varlatch
for that version (Sigstore, fetched trusted root), then that each file
matches its line in SHA256SUMS under the given name. Exits 0 only if every
check passes. install.sh and install.ps1 run it before installing anything.

  --trusted-root <file>   use this Sigstore trusted root instead of fetching it
`

// verifyRelease is the verify-release command; stdout gets the results.
func verifyRelease(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	version := fs.String("version", "", "")
	sumsPath := fs.String("sums", "", "")
	bundlePath := fs.String("bundle", "", "")
	trustedRoot := fs.String("trusted-root", "", "")
	var files fileFlags
	fs.Var(&files, "file", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *version == "" || *sumsPath == "" || *bundlePath == "" {
		fmt.Fprint(stderr, verifyReleaseUsage)
		return 2
	}
	fail := func(format string, a ...any) int {
		// The fail-safe, as on every CLI failure.
		fmt.Fprintln(stderr, clientctx.MaskUserinfoInText("varlatch verify-release: "+fmt.Sprintf(format, a...)))
		return 1
	}

	// The precise layer: an error repeating a path given here shows it masked.
	given := []string{*sumsPath, *bundlePath, *trustedRoot}
	for _, f := range files {
		path, _, _ := strings.Cut(f, "=")
		given = append(given, path)
	}
	masked := func(err error) string { return maskPaths(err.Error(), given) }

	sums, err := os.ReadFile(*sumsPath)
	if err != nil {
		return fail("%s", masked(err))
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fail("%s", masked(err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var trusted root.TrustedMaterial
	if *trustedRoot != "" {
		if trusted, err = root.NewTrustedRootFromPath(*trustedRoot); err != nil {
			return fail("reading the trusted root: %s", masked(err))
		}
	} else {
		cache := ""
		if dir, err := os.UserCacheDir(); err == nil {
			cache = filepath.Join(dir, "varlatch", "sigstore")
		}
		if trusted, err = release.LiveTrustedRoot(ctx, cache); err != nil {
			return fail("%v", err)
		}
	}
	v, err := release.NewVerifier(trusted)
	if err != nil {
		return fail("%v", err)
	}
	checked, err := v.VerifySums(*version, sums, bundle)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(stdout, "SHA256SUMS of %s is signed by %s\n", *version, release.Identity(*version))
	for _, f := range files {
		path, name, ok := strings.Cut(f, "=")
		if !ok || path == "" || name == "" {
			// Masked before it is quoted (the precise layer); fail is the fail-safe.
			return fail("--file needs <path>=<name>, got %q", clientctx.MaskURLInValue(f))
		}
		r, err := os.Open(path)
		if err != nil {
			return fail("%s", masked(err))
		}
		err = checked.Check(name, r)
		_ = r.Close()
		if err != nil {
			return fail("%s: %s", clientctx.MaskURLInValue(path), masked(err))
		}
		fmt.Fprintf(stdout, "%s matches SHA256SUMS (%s)\n", clientctx.MaskURLInValue(path), name)
	}
	return 0
}

// maskPaths is text with each path given on the command line, where it
// appears, masked with MaskURLInValue (the precise layer: a path holding a
// URL's user name and password shows them as [redacted]).
func maskPaths(text string, paths []string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if m := clientctx.MaskURLInValue(p); m != p {
			text = strings.ReplaceAll(text, p, m)
		}
	}
	return text
}
