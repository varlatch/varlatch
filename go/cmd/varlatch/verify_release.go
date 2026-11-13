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
		fmt.Fprintf(stderr, "varlatch verify-release: "+format+"\n", a...)
		return 1
	}

	sums, err := os.ReadFile(*sumsPath)
	if err != nil {
		return fail("%v", err)
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fail("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var trusted root.TrustedMaterial
	if *trustedRoot != "" {
		if trusted, err = root.NewTrustedRootFromPath(*trustedRoot); err != nil {
			return fail("reading the trusted root: %v", err)
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
			return fail("--file needs <path>=<name>, got %q", f)
		}
		r, err := os.Open(path)
		if err != nil {
			return fail("%v", err)
		}
		err = checked.Check(name, r)
		_ = r.Close()
		if err != nil {
			return fail("%s: %v", path, err)
		}
		fmt.Fprintf(stdout, "%s matches SHA256SUMS (%s)\n", path, name)
	}
	return 0
}
