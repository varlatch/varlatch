// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/release"
)

// selfUpdateUsage is what `varlatch help self-update`, `self-update --help`
// and a usage error print: the Go CLI's own forms (an accepted difference,
// go/README.md `self-update-usage`; the TypeScript CLI replaces its .cjs
// and may skip the signature).
const selfUpdateUsage = `Usage:
  varlatch self-update [<version>] [--check [--json]] [--yes] [--prerelease] [--allow-downgrade]
               (replaces this varlatch with a release's, from GitHub, after checking that SHA256SUMS is signed by
                the release workflow of varlatch/varlatch for that version and that the file matches it; never an
                older release unless --allow-downgrade, a prerelease only from a prerelease or with --prerelease.
                A copy installed with Homebrew or winget is updated with that package manager)`

// SelfUpdateHelp is selfUpdateUsage, for the transcripts' accepted
// difference.
const SelfUpdateHelp = selfUpdateUsage

// selfUpdateSource is where releases come from: GitHub, always, in a
// release build. Only a test build replaces it (selfupdate_testseam.go).
var selfUpdateSource = func(r *Run) selfupdate.Source {
	cache := ""
	if dir, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(dir, "varlatch", "sigstore")
	}
	return selfupdate.GitHub(r.UserAgent(), cache)
}

// selfUpdateTimeout bounds a whole update, the prompt aside.
const selfUpdateTimeout = 10 * time.Minute

// selfUpdateCommand is `self-update`'s partial: every form (slice 6.7a of
// internal docs/design/go-step6.md).
func selfUpdateCommand(r *Run) (bool, error) {
	return true, r.selfUpdate()
}

func (r *Run) selfUpdate() error {
	parsed, err := strictOptions("self-update", r.Args, OptionSpec{
		Values:      []string{"--repo"},
		Booleans:    []string{"--check", "--json", "--yes", "--allow-unverified", "--prerelease", "--allow-downgrade"},
		Positionals: 1,
	}, selfUpdateUsage)
	if err != nil {
		return err
	}
	// The TypeScript CLI's --repo and VARLATCH_RELEASE_REPO choose another
	// repository; the signature check here pins varlatch/varlatch's release
	// workflow, so only that one is accepted. --allow-unverified changes
	// nothing: every release of the Go line is signed and always checked.
	repo, given := parsed.Value("--repo")
	if !given {
		repo = r.Getenv("VARLATCH_RELEASE_REPO")
	}
	if repo != "" && repo != release.Repository {
		return UsageErrorWithUsage("varlatch self-update: releases come from "+release.Repository+" only (the signature check pins its release workflow), not "+shownArgument(repo), "\n"+selfUpdateUsage)
	}
	if parsed.Has("--allow-unverified") {
		if err := r.warn("varlatch self-update: --allow-unverified changes nothing: every release is verified"); err != nil {
			return err
		}
	}
	version := ""
	if len(parsed.Positionals) > 0 {
		version = parsed.Positionals[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), selfUpdateTimeout)
	defer cancel()
	src := selfUpdateSource(r)
	exe, err := os.Executable()
	if err != nil {
		return Fail("varlatch self-update: cannot find this varlatch's file: "+err.Error(), ExitFailure)
	}
	target, err := selfupdate.Locate(exe)
	if err != nil {
		return Fail("varlatch self-update: cannot find this varlatch's file: "+err.Error(), ExitFailure)
	}
	plan, err := selfupdate.Choose(ctx, src, selfupdate.Options{
		Version: version, Prerelease: parsed.Has("--prerelease"), AllowDowngrade: parsed.Has("--allow-downgrade"),
		Current: buildinfo.Version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	})
	if parsed.Has("--check") {
		if err != nil {
			return selfUpdateError(err)
		}
		if parsed.Has("--json") {
			return r.printJSON(jsjson.Object{
				{Key: "current", Value: plan.Current},
				{Key: "latest", Value: plan.Latest},
				{Key: "updateAvailable", Value: plan.UpdateAvailable},
				{Key: "releaseUrl", Value: plan.ReleaseURL},
				{Key: "install", Value: string(target.Kind)},
				{Key: "path", Value: target.Path},
			})
		}
		if plan.UpdateAvailable {
			return r.println("varlatch " + plan.Latest + " is available (this is " + plan.Current + "): " + plan.ReleaseURL)
		}
		return r.println("varlatch " + plan.Current + " is up to date.")
	}
	if message := target.PackageManaged(); message != "" {
		return Fail("varlatch self-update: "+message, ExitFailure)
	}
	if err != nil {
		return selfUpdateError(err)
	}
	if !plan.UpdateAvailable && !plan.Downgrade {
		return r.println("varlatch " + plan.Current + " is up to date.")
	}

	if err := r.println("Downloading " + selfupdate.Asset(plan.Latest, runtime.GOOS, runtime.GOARCH) + "..."); err != nil {
		return err
	}
	d, err := selfupdate.Fetch(ctx, src, plan, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return selfUpdateError(err)
	}
	for _, line := range []string{
		"",
		"  varlatch " + plan.Current + " -> " + plan.Latest,
		"  install:   " + target.Path,
		"  checksum:  ok (SHA256SUMS)",
		"  signature: verified (" + d.Identity + ")",
		"  changes:   " + plan.ReleaseURL,
		"",
	} {
		if err := r.println(line); err != nil {
			return err
		}
	}
	if !parsed.Has("--yes") {
		if !isTerminal(r.Stdin) {
			return Fail("varlatch self-update: not a terminal: pass --yes to update without a prompt. Nothing was installed.", ExitFailure)
		}
		ok, err := newTerminalPrompter(r).confirm("Replace "+target.Path+" with "+plan.Latest+"?", false)
		if err != nil {
			return err
		}
		if !ok {
			return r.println("Nothing was installed.")
		}
	}
	if err := selfupdate.Install(ctx, d, target.Path); err != nil {
		return selfUpdateError(err)
	}
	return r.println("Installed varlatch " + plan.Latest + " at " + target.Path + ".")
}

// selfUpdateError is an update's failure with its exit status: 69 when a
// host could not be reached, 64 for a request refused, 1 otherwise.
func selfUpdateError(err error) error {
	var e *selfupdate.Error
	if !errors.As(err, &e) {
		return Fail("varlatch self-update: "+err.Error(), ExitFailure)
	}
	switch {
	case e.Usage:
		return UsageErrorWithUsage("varlatch self-update: "+e.Message, "\n"+selfUpdateUsage)
	case e.Unreachable:
		return Fail("varlatch self-update: "+e.Message, ExitUnavailable)
	}
	return Fail("varlatch self-update: "+e.Message, ExitFailure)
}
