// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// upgradeUsage is what `varlatch help upgrade`, `upgrade --help` and a
// usage error print: a Go installation's forms (an accepted difference,
// go/README.md `upgrade-usage`; the TypeScript CLI's upgrade is a Compose
// installation's, varlatch-ts upgrade).
const upgradeUsage = `Usage:
  varlatch upgrade [<version>] [--prerelease] [--accept-not-rollback-safe] [--end-rollback-window] [--yes] [--config <file>]
  varlatch upgrade --check [--prerelease] [--json] [--config <file>]
  varlatch upgrade --rollback [--yes] [--accept-data-loss] [--config <file>]
               (a Go installation's upgrade, on its host, as root: downloads the release's varlatch, varlatchd and
                release.json, checks that SHA256SUMS is signed by the release workflow of varlatch/varlatch for that
                version, takes an encrypted snapshot kept 30 days, updates a copy of the database, swaps the binaries
                and the database, restarts varlatchd and keeps the new release only when its health checks pass;
                anything else ends with the previous release serving. While a migration's rollback window is open, a
                release that ends it is upgraded to only once confirmed (--end-rollback-window without a prompt).
                --check looks for a newer release and records what it found for the dashboard's notice. --rollback
                returns to the release the last upgrade came from: keeping every change when that release opens the
                database as it is, else restoring the pre-upgrade snapshot, after listing what is lost
                (--accept-data-loss, for scripts). A Compose installation's upgrade is varlatch-ts upgrade)`

// UpgradeHelp is upgradeUsage, for the transcripts' accepted difference.
const UpgradeHelp = upgradeUsage

// upgradeService is varlatchd's service: the systemd unit install.sh
// --server installs. Only the tests replace it.
var upgradeService = func() upgrade.Service { return upgrade.Systemd{Unit: "varlatchd"} }

// upgradeTimeout bounds a whole upgrade, the prompt aside.
const upgradeTimeout = 30 * time.Minute

// composeUpgradeOptions are the TypeScript upgrade's options for a Compose
// installation: refused, naming varlatch-ts.
var composeUpgradeOptions = []string{"--dir", "--backup-dir", "--bek-file", "--bek-passphrase-file", "--kek-file", "--destination",
	"--destinations-file", "--scratch-dir", "--timeout-seconds", "--skip-db-backup", "--kek-backup-verified", "--release-dir"}

// upgradeCommand is `upgrade`'s partial: every form (slice 6.6b of
// internal docs/design/go-step6.md).
func upgradeCommand(r *Run) (bool, error) {
	for _, a := range r.Args {
		name, _, _ := strings.Cut(a, "=")
		for _, o := range composeUpgradeOptions {
			if name == o {
				return true, composeRefusalOf(r, "upgrade", o)
			}
		}
	}
	return true, r.upgrade()
}

func (r *Run) upgrade() error {
	parsed, err := strictOptions("upgrade", r.Args, OptionSpec{
		Values:      []string{"--config", "--repo"},
		Booleans:    []string{"--check", "--json", "--yes", "--prerelease", "--accept-not-rollback-safe", "--end-rollback-window", "--rollback", "--accept-data-loss"},
		Positionals: 1,
	}, upgradeUsage)
	if err != nil {
		return err
	}
	repo, given := parsed.Value("--repo")
	if !given {
		repo = r.Getenv("VARLATCH_RELEASE_REPO")
	}
	if repo != "" && repo != release.Repository {
		return UsageErrorWithUsage("varlatch upgrade: releases come from "+release.Repository+" only (the signature check pins its release workflow), not "+shownArgument(repo), "\n"+upgradeUsage)
	}
	check := parsed.Has("--check")
	rollback := parsed.Has("--rollback")
	if rollback && (check || len(parsed.Positionals) > 0 || parsed.Has("--prerelease") || parsed.Has("--accept-not-rollback-safe") || parsed.Has("--end-rollback-window") || parsed.Has("--json")) {
		return UsageErrorWithUsage("varlatch upgrade: --rollback returns to the last upgrade's previous release: it takes no version, --check, --prerelease, --json, --accept-not-rollback-safe or --end-rollback-window", "\n"+upgradeUsage)
	}
	if parsed.Has("--accept-data-loss") && !rollback {
		return UsageErrorWithUsage("varlatch upgrade: --accept-data-loss goes with --rollback", "\n"+upgradeUsage)
	}
	if parsed.Has("--json") && !check {
		return UsageErrorWithUsage("varlatch upgrade: --json goes with --check", "\n"+upgradeUsage)
	}
	if check && (parsed.Has("--accept-not-rollback-safe") || parsed.Has("--yes") || parsed.Has("--end-rollback-window")) {
		return UsageErrorWithUsage("varlatch upgrade: --check upgrades nothing: it takes no --yes, --accept-not-rollback-safe or --end-rollback-window", "\n"+upgradeUsage)
	}
	config, given := parsed.Value("--config")
	if !given {
		config = DefaultVarlatchdConfig
	}
	version := ""
	if len(parsed.Positionals) > 0 {
		version = parsed.Positionals[0]
	}
	if runtime.GOOS != "linux" {
		return Fail("varlatch upgrade: a Go installation's server runs on Linux; run this on its host", ExitUsage)
	}
	if !check && !asRoot() {
		return Fail("varlatch upgrade: replacing varlatchd and its database needs root: run it as sudo varlatch upgrade. Nothing was changed.", ExitDenied)
	}
	varlatchd, err := r.locateVarlatchd("varlatch upgrade")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), upgradeTimeout)
	defer cancel()
	u := &upgrade.Upgrader{BinDir: filepath.Dir(varlatchd), ConfigPath: config, Service: upgradeService(), Log: func(line string) { _ = r.println(line) }}
	if check {
		return r.upgradeCheck(ctx, u, version, parsed.Has("--prerelease"), parsed.Has("--json"))
	}

	// An upgrade left pending is finished or undone first, and nothing else.
	if j, err := u.Recover(ctx); err != nil {
		return upgradeFailure(err)
	} else if j != nil {
		return r.println(recoveredMessage(j))
	}
	if rollback {
		return r.upgradeRollback(ctx, u, parsed.Has("--yes"), parsed.Has("--accept-data-loss"))
	}
	inst, err := u.Inspect(ctx)
	if err != nil {
		return Fail("varlatch upgrade: "+err.Error()+". Nothing was changed.", ExitFailure)
	}
	src := selfUpdateSource(r)
	plan, err := selfupdate.Choose(ctx, src, selfupdate.Options{
		Version: version, Prerelease: parsed.Has("--prerelease"), Current: inst.Version, GOOS: "linux", GOARCH: runtime.GOARCH,
	})
	if err != nil {
		return upgradeFailure(err)
	}
	if !plan.UpdateAvailable {
		return r.println("varlatchd " + inst.Version + " is up to date.")
	}
	rel, err := upgrade.Fetch(ctx, src, plan.Latest, runtime.GOARCH)
	if err != nil {
		return upgradeFailure(err)
	}
	// Before anything is asked or recorded (the migration's window below).
	if err := upgrade.SchemaRefusal(inst, rel.Version, rel.Manifest); err != nil {
		return upgradeFailure(err)
	}
	safe := upgrade.RollbackSafe(rel.Manifest, inst)
	// Decision 17: a release that ends a migration's rollback window is
	// upgraded to only once the operator confirms it, while the window is
	// open (Go's migration journal, read as root on this host).
	endsWindow, err := windowEnding(inst.DataDir, rel.Version, rel.Manifest.EndsRollbackWindow(), time.Now())
	if err != nil {
		return Fail("varlatch upgrade: "+err.Error()+" Nothing was changed.", ExitFailure)
	}
	goingBack := "Going back"
	if upgrade.ReturnsTo(inst.Version) {
		goingBack += " (varlatch upgrade --rollback)"
	}
	lines := []string{
		"",
		"  varlatchd " + inst.Version + " -> " + rel.Version + " (schema version " + fmt.Sprint(inst.Schema) + " -> " + fmt.Sprint(rel.Manifest.SchemaVersion) + ")",
		"  binaries:  " + u.BinDir,
		"  checksum:  ok (SHA256SUMS)",
		"  signature: verified (" + release.Identity(rel.Version) + ")",
		"  changes:   " + plan.ReleaseURL,
	}
	if safe {
		lines = append(lines, "  rollback:  safe: "+rel.Version+"'s release.json declares it rollback-safe for "+inst.Version+", and "+inst.Version+" can open the",
			"             upgraded database. "+goingBack+" keeps every change")
	} else if !upgrade.DeclaredRollbackSafe(rel.Manifest, inst) {
		checked := "no release"
		if p := rel.Manifest.Previous; p != nil {
			checked = p.Version
		}
		lines = append(lines, "  rollback:  NOT safe: "+rel.Version+"'s release.json does not declare it rollback-safe for "+inst.Version+" (it was checked",
			"             against "+checked+"). "+goingBack+" means restoring the pre-upgrade snapshot,",
			"             which loses every change made after it. "+notCounted)
	} else {
		lines = append(lines, "  rollback:  NOT safe: once upgraded, the database needs varlatchd of schema "+fmt.Sprint(rel.Manifest.CompatibleFrom)+" or later,",
			"             which "+inst.Version+" (schema "+fmt.Sprint(inst.Schema)+") is not. "+goingBack+" means",
			"             restoring the pre-upgrade snapshot, which loses every change made after it. "+notCounted)
	}
	if endsWindow {
		lines = append(lines, "  migration: "+release.RollbackWindowNotice)
	}
	lines = append(lines, "")
	for _, line := range lines {
		if err := r.println(line); err != nil {
			return err
		}
	}
	confirmed := false
	if endsWindow && !parsed.Has("--end-rollback-window") {
		if !isTerminal(r.Stdin) || parsed.Has("--yes") {
			return Fail("varlatch upgrade: "+rel.Version+" ends the migration's rollback window (above): pass --end-rollback-window to upgrade anyway, or end the window first (varlatch migrate --finish). Nothing was changed.", ExitFailure)
		}
		ok, err := newTerminalPrompter(r).confirm("Upgrade to "+rel.Version+", which ends the migration's rollback window?", false)
		if err != nil {
			return err
		}
		if !ok {
			return r.println("Nothing was changed.")
		}
		confirmed = true
	}
	if !safe && !parsed.Has("--accept-not-rollback-safe") {
		if !isTerminal(r.Stdin) || parsed.Has("--yes") {
			return Fail("varlatch upgrade: "+rel.Version+" is not rollback-safe for this installation: pass --accept-not-rollback-safe after reading why above. Nothing was changed.", ExitFailure)
		}
		ok, err := newTerminalPrompter(r).confirm("Upgrade to "+rel.Version+", which is not rollback-safe?", false)
		if err != nil {
			return err
		}
		if !ok {
			return r.println("Nothing was changed.")
		}
	} else if !parsed.Has("--yes") && !confirmed {
		if !isTerminal(r.Stdin) {
			return Fail("varlatch upgrade: not a terminal: pass --yes to upgrade without a prompt. Nothing was changed.", ExitFailure)
		}
		ok, err := newTerminalPrompter(r).confirm("Upgrade varlatchd to "+rel.Version+"?", false)
		if err != nil {
			return err
		}
		if !ok {
			return r.println("Nothing was changed.")
		}
	}
	if endsWindow {
		// Recorded before anything is upgraded, in Go's journal beside the
		// running varlatchd: from now no reverse starts, even if the
		// upgrade is undone (its way back ends with the window).
		host := &migrate.Host{Varlatchd: varlatchd, Config: config, Run: migrate.ExecRunner{Env: varlatchdEnviron(r)}}
		if err := migrate.EndRollbackWindow(ctx, host, inst.DataDir, rel.Version, time.Now()); err != nil {
			return Fail("varlatch upgrade: recording the end of the migration's rollback window: "+err.Error()+". Nothing was changed.", ExitFailure)
		}
		if err := r.println("The migration's rollback window ends: recorded in its journal (varlatch migrate --rollback now refuses)."); err != nil {
			return err
		}
	}
	if _, err := u.Run(ctx, inst, rel); err != nil {
		return upgradeFailure(err)
	}
	done := "Upgraded to " + rel.Version + ". The pre-upgrade snapshot is kept 30 days with the upgrade."
	if upgrade.ReturnsTo(inst.Version) {
		done += " varlatch upgrade --rollback goes back to " + inst.Version + "."
	}
	return r.println(done)
}

// windowEnding is whether upgrading to version (whose manifest ends the
// rollback window when ends) ends an open migration's rollback window on
// the installation whose data directory is dataDir. While a reverse is
// under way it refuses: the window's end is recorded on an open journal
// only, and a release that cannot reverse must not run mid-reverse.
func windowEnding(dataDir, version string, ends bool, now time.Time) (bool, error) {
	if !ends {
		return false, nil
	}
	open, err := migrate.RollbackWindowOpen(dataDir, now)
	if err != nil {
		return false, fmt.Errorf("the migration journal in %s: %v.", dataDir, err)
	}
	if !open {
		return false, nil
	}
	phase, err := migrate.ReverseUnderWay(dataDir)
	if err != nil {
		return false, fmt.Errorf("the migration journal in %s: %v.", dataDir, err)
	}
	if phase != "" {
		return false, fmt.Errorf("a rollback is under way (the migration is in phase %s): %s ends its rollback window, so finish or abort the rollback first (varlatch migrate --resume, or --abort).", phase, version)
	}
	return true, nil
}

// upgradeCheck is `upgrade --check`: the newest release this host may go
// to, recorded for the dashboard's notice (ADR-0049) when no version was
// named, as the TypeScript line records an unpinned check.
func (r *Run) upgradeCheck(ctx context.Context, u *upgrade.Upgrader, version string, prerelease, asJSON bool) error {
	out, err := upgradeVersion(ctx, filepath.Join(u.BinDir, "varlatchd"))
	if err != nil {
		return Fail("varlatch upgrade --check: "+err.Error(), ExitFailure)
	}
	src := selfUpdateSource(r)
	plan, err := selfupdate.Choose(ctx, src, selfupdate.Options{Version: version, Prerelease: prerelease || release.Prerelease(out), Current: out, GOOS: "linux", GOARCH: runtime.GOARCH})
	if version == "" {
		published := ""
		if err == nil {
			_, published, _ = selfupdate.Newest(ctx, src, prerelease || release.Prerelease(out))
		}
		if rerr := r.recordReleaseCheck(ctx, u, plan, published, err); rerr != nil {
			if werr := r.warn("varlatch upgrade --check: not recorded for the dashboard: " + rerr.Error()); werr != nil {
				return werr
			}
		}
	}
	if err != nil {
		return upgradeFailure(err)
	}
	if asJSON {
		return r.printJSON(jsjson.Object{
			{Key: "current", Value: plan.Current},
			{Key: "latest", Value: plan.Latest},
			{Key: "updateAvailable", Value: plan.UpdateAvailable},
			{Key: "releaseUrl", Value: plan.ReleaseURL},
		})
	}
	if plan.UpdateAvailable {
		return r.println("varlatchd " + plan.Latest + " is available (this host runs " + plan.Current + "): " + plan.ReleaseURL + ". Upgrade with sudo varlatch upgrade.")
	}
	return r.println("varlatchd " + plan.Current + " is up to date.")
}

// recordReleaseCheck records one check through `varlatchd admin
// release-check record`: what it found, or why it found nothing.
func (r *Run) recordReleaseCheck(ctx context.Context, u *upgrade.Upgrader, plan selfupdate.Plan, published string, found error) error {
	args := []string{"admin", "release-check", "record", "--repo", release.Repository}
	if found == nil {
		args = append(args, "--version", plan.Latest)
		if published != "" {
			args = append(args, "--published-at", published)
		}
	} else {
		args = append(args, "--failed", releaseCheckFailure(found))
	}
	return runQuiet(ctx, filepath.Join(u.BinDir, "varlatchd"), append(args, "--config", u.ConfigPath)...)
}

// releaseCheckFailure names a failed look in the record's words.
func releaseCheckFailure(err error) string {
	var e *selfupdate.Error
	switch {
	case errors.As(err, &e) && e.Unreachable:
		return "unreachable"
	case strings.Contains(err.Error(), "rate limit"):
		return "rate-limited"
	case strings.Contains(err.Error(), "no release"):
		return "not-found"
	}
	return "invalid-answer"
}

// upgradeFailure is an upgrade's failure with its exit status: 69 when a
// host could not be reached, 64 for a request refused, 1 otherwise.
func upgradeFailure(err error) error {
	var se *selfupdate.Error
	if errors.As(err, &se) {
		switch {
		case se.Usage:
			return UsageErrorWithUsage("varlatch upgrade: "+se.Message, "\n"+upgradeUsage)
		case se.Unreachable:
			return Fail("varlatch upgrade: "+se.Message, ExitUnavailable)
		}
		return Fail("varlatch upgrade: "+se.Message, ExitFailure)
	}
	return Fail("varlatch upgrade: "+err.Error(), ExitFailure)
}

// DefaultVarlatchdConfig is a Go installation's varlatchd.conf, whose
// directory also holds the upgrade journal.
const DefaultVarlatchdConfig = "/etc/varlatch/varlatchd.conf"

// upgradeVersion is the release a varlatchd says it is.
func upgradeVersion(ctx context.Context, varlatchd string) (string, error) {
	out, err := exec.CommandContext(ctx, varlatchd, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %v", varlatchd, err)
	}
	v, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "varlatchd ")
	if !ok || !release.ValidVersion(v) {
		return "", fmt.Errorf("%s is not a release's varlatchd (it says %q)", varlatchd, Printable(strings.TrimSpace(string(out))))
	}
	return v, nil
}

// runQuiet runs a program and keeps what it said for an error.
func runQuiet(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		if text := strings.TrimSpace(string(out)); text != "" {
			return errors.New(text)
		}
		return err
	}
	return nil
}

// upgradeRollback is `upgrade --rollback`: the plan shown first (and, when
// the snapshot is restored, every change it loses), then the rollback.
func (r *Run) upgradeRollback(ctx context.Context, u *upgrade.Upgrader, yes, acceptLoss bool) error {
	plan, err := u.PlanRollback(ctx)
	if err != nil {
		return Fail("varlatch upgrade --rollback: "+err.Error()+". Nothing was changed.", ExitFailure)
	}
	last := plan.Last
	lines := []string{"", "  varlatchd " + last.To + " -> back to " + last.From, "  rule:      " + plan.Rule}
	if r := last.LastRollback; r != nil {
		lines = append(lines, "  before:    a rollback begun before was undone ("+Printable(r.At)+": "+Printable(r.Reason)+")")
	}
	if plan.Migration != "" {
		lines = append(lines, "  migration: "+plan.Migration)
	}
	if plan.Safe {
		lines = append(lines, "  database:  kept as it is, so every change made since the upgrade stays")
	} else {
		lines = append(lines,
			"  database:  the pre-upgrade snapshot is restored",
			"  snapshot:  "+last.Snapshot+" (taken "+last.SnapshotAt+")",
		)
		lines = append(lines, lostLines(plan.Lost)...)
		lines = append(lines, "  NOT COUNTED: "+notCounted, "             The database the rollback replaces is kept with it for 30 days.")
	}
	lines = append(lines, "")
	for _, line := range lines {
		if err := r.println(line); err != nil {
			return err
		}
	}
	switch {
	case !plan.Safe && !acceptLoss:
		if !isTerminal(r.Stdin) || yes {
			return Fail("varlatch upgrade --rollback: restoring the snapshot loses the changes listed above: pass --accept-data-loss to go on. Nothing was changed.", ExitFailure)
		}
		ok, err := newTerminalPrompter(r).confirm("Restore the pre-upgrade snapshot and lose these changes?", false)
		if err != nil {
			return err
		}
		if !ok {
			return r.println("Nothing was changed.")
		}
	case plan.Safe && !yes:
		if !isTerminal(r.Stdin) {
			return Fail("varlatch upgrade --rollback: not a terminal: pass --yes to roll back without a prompt. Nothing was changed.", ExitFailure)
		}
		ok, err := newTerminalPrompter(r).confirm("Roll back to "+last.From+"?", false)
		if err != nil {
			return err
		}
		if !ok {
			return r.println("Nothing was changed.")
		}
	}
	// What was made between the list and the stop is lost too: asked again,
	// and never taken for accepted without a terminal.
	grown := func(now *upgrade.Changes) (bool, error) {
		lines := append([]string{"", "  More changes were made before varlatchd stopped. All the rollback loses now:"}, lostLines(now)...)
		for _, line := range append(lines, "") {
			if err := r.println(line); err != nil {
				return false, err
			}
		}
		if !isTerminal(r.Stdin) {
			return false, nil
		}
		return newTerminalPrompter(r).confirm("Restore the pre-upgrade snapshot and lose these changes?", false)
	}
	// Its time begins now: the prompt may have waited.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), upgradeTimeout)
	defer cancel()
	j, err := u.Rollback(ctx, plan, grown)
	if err != nil {
		return upgradeFailure(err)
	}
	if err := r.println("Rolled back to " + last.From + "."); err != nil {
		return err
	}
	if plan.Safe {
		return nil
	}
	for _, line := range afterRestore(last.From, filepath.Join(j.Work, "original"), upgrade.Held(j.DataDir)) {
		if err := r.println(line); err != nil {
			return err
		}
	}
	return nil
}

// notCounted is what a snapshot restore also loses or reverts beyond the
// audited changes it lists.
const notCounted = "Only audited changes are counted. Also lost or reverted: sign-ins and sign-outs, pending approvals, and delivery and sync cursors (webhooks may be delivered again, and sync targets converge back)."

// undoneShown is how many of them are shown, the newest.
const undoneShown = 200

// lostLines are the changes a restore loses, what it takes back first.
func lostLines(lost *upgrade.Changes) []string {
	lines := undoneLines(lost)
	lines = append(lines, fmt.Sprintf("  LOST:      %d audit events recorded since %s (a few in the snapshot's last minute may be in it):", lost.Total, lost.Since))
	types := make([]string, 0, len(lost.ByType))
	for t := range lost.ByType {
		types = append(types, t)
	}
	slices.Sort(types)
	for _, t := range types {
		lines = append(lines, fmt.Sprintf("             %6d  %s", lost.ByType[t], Printable(t)))
	}
	if len(lost.Latest) > 0 {
		lines = append(lines, "             the newest:")
		for _, c := range lost.Latest {
			org := "the installation"
			if c.OrganizationID != nil {
				org = Printable(*c.OrganizationID)
			}
			lines = append(lines, "               "+Printable(c.OccurredAt)+"  "+Printable(c.EventType)+" ("+Printable(c.Decision)+", "+org+")")
		}
	}
	return lines
}

// undoneLines are the revocations, removals, rotations, replacements,
// deletions and freezes the restore takes back, listed before anything
// else it loses.
func undoneLines(lost *upgrade.Changes) []string {
	if lost.RevocationsTotal == 0 {
		return []string{"  UNDONE:    no revocations, removals, rotations, replacements, deletions and freezes were recorded since the snapshot"}
	}
	lines := []string{fmt.Sprintf("  UNDONE:    revocations, removals, rotations, replacements, deletions and freezes made since the snapshot that the restore undoes (%d):", lost.RevocationsTotal)}
	for _, c := range lost.Revocations[:min(len(lost.Revocations), undoneShown)] {
		org := "the installation"
		if c.OrganizationID != nil {
			org = Printable(*c.OrganizationID)
		}
		what := ""
		if c.Resource != nil {
			what = " " + Printable(*c.Resource)
		}
		lines = append(lines, "               "+Printable(c.OccurredAt)+"  "+Printable(c.EventType)+" ("+org+")"+what)
	}
	if more := lost.RevocationsTotal - undoneShown; more > 0 {
		lines = append(lines, fmt.Sprintf("               and %d more (varlatchd admin changes --since %s --json lists them all)", more, lost.Since))
	}
	return lines
}

// afterRestore is what to do once a restore has taken changes back:
// with the commands the release returned to has, and no command run for
// the operator.
func afterRestore(release, kept string, held bool) []string {
	lines := []string{""}
	if held {
		lines = append(lines,
			"The installation is held after the restore: it serves, but what it would deliver or destroy on its own (webhooks, sync,",
			"deletions) waits until you have gone through the list below and run sudo varlatch admin restore resume.",
			"")
	}
	return append(lines,
		"What to do now: the restore took the changes listed above back.",
		"  - Revoke again each credential listed as revoked (varlatch credential revoke <identity-id> <credential-id>), retire again",
		"    each identity listed as retired (varlatch identity retire <identity-id> --confirm <name>), revoke again each grant,",
		"    capability, binding, invitation or requirement, and remove again each member, as they are listed.",
		"  - Rotate again each Secret listed as rotated and replace again each credential listed as replaced: the old values are",
		"    current again. Delete again what is listed as deleted.",
		"  - Sign-outs since the snapshot are undone: a session ended since then is valid again until it expires. "+release+" has no",
		"    command that signs everyone out; ask the people affected to sign out of the dashboard and in again.",
		"  - Approvals pending at the snapshot are pending again; webhooks may deliver events again; sync targets converge back to",
		"    the restored values.",
		"  The database the rollback replaced is kept in "+kept+" (30 days).",
	)
}

// recoveredMessage says what Recover did with an interrupted upgrade or
// rollback.
func recoveredMessage(j *journal.Journal) string {
	what := "upgrade"
	again := "Run varlatch upgrade again to upgrade."
	if j.Kind == journal.Rollback {
		what = "rollback"
		again = "Run varlatch upgrade --rollback again to go back."
	}
	if j.State == journal.Done {
		if j.Kind == journal.Rollback {
			return fmt.Sprintf("Finished the interrupted rollback from %s to %s: %s serves, after its health checks.", j.From, j.To, j.To)
		}
		return fmt.Sprintf("Finished the interrupted upgrade from %s to %s: %s serves. Run varlatch upgrade again to look for a newer release.", j.From, j.To, j.To)
	}
	return fmt.Sprintf("Undid the interrupted %s from %s to %s (%s): %s serves. %s", what, j.From, j.To, j.Reason, j.From, again)
}
