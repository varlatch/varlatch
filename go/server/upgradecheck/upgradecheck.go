// SPDX-License-Identifier: AGPL-3.0-or-later

// Package upgradecheck is the Release tab's pre-flight (ADR-0065 Decisions
// 3, 4 and 8, phase 1): what stands between this installation and the
// release the host's check verified, line by line, each pass, fail or
// unknown, each failure with what to do. It judges; it upgrades nothing.
// The host's records it reads (the release check, the verified target) are
// display state that varlatchd can write: an upgrade verifies the release
// again from scratch, and the engine refuses for itself what this says.
//
// On a systemd host the seventh line (phase 2) is the host helper's: it
// is installed, accepts requests, and its heartbeat comes from the last
// release check. The image has no helper (phase 3), so no such line. The
// upgrade button is offered only when every line passes (All).
package upgradecheck

import (
	"fmt"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// Deployment is how varlatchd runs, known, not chosen (Decision 8): from
// the systemd unit install.sh --server installs, or as the single-container
// image (which sets VARLATCH_IMAGE).
type Deployment string

const (
	Systemd Deployment = "systemd"
	Image   Deployment = "image"
)

// The checklist's windows (Decision 8): a daily check and its slack, and a
// day for the last delivery.
const (
	CheckMaxAge    = 36 * time.Hour
	DeliveryMaxAge = 24 * time.Hour
	// FreeMargin is the free space kept beyond the snapshot and the copy
	// (the doctor's disk check's margin).
	FreeMargin = 64 << 20
)

// Status is a line's outcome.
type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

// Line is one line of the checklist.
type Line struct {
	ID     string
	Status Status
	Title  string
	Detail string
	// Remedy is what to do, "" when the line passes.
	Remedy string
}

// The lines' ids, in the order the tab shows them.
const (
	LineReleaseCheck = "release-check"
	LineBackup       = "backup"
	LineCustody      = "custody"
	LineDisk         = "disk"
	LineInTheWay     = "in-the-way"
	LineRollbackSafe = "rollback-safe"
	LineHelper       = "helper"
)

// HeartbeatSlack is how much earlier than the release check's last attempt
// the helper's heartbeat may be and still count as that check's: the same
// run records both, the heartbeat after the check.
const HeartbeatSlack = 10 * time.Minute

// Helper is the host helper's record of itself (upgrade-request/
// helper.json), display state.
type Helper struct {
	// Err is a record that cannot be read; Present whether there is one.
	Err     error
	Present bool
	Enabled bool
	Version string
	At      time.Time
}

// Backups is what the server knows of its backups.
type Backups struct {
	// Err is a status that could not be read.
	Err error
	// Destination is the configured backup_destination, "" for none.
	Destination string
	// Last is when the newest backup of this installation was made, zero
	// for none; Delivered when its upload completed, zero for not.
	Last, Delivered time.Time
}

// Custody is whether each key has a Custody Attestation (ADR-0035 D9).
type Custody struct {
	Err            error
	RootKEKVersion int64
	RootKEK        bool
	BackupKey      bool
}

// Disk is the data directory's free space and the database's size with its
// log, as the doctor's disk check measures them.
type Disk struct {
	Err      error
	Free     uint64
	Database int64
}

// Host is what varlatchd knows of its host, read when the tab asks.
type Host struct {
	Deployment Deployment
	// Schema is this varlatchd's schema version.
	Schema int64
	Backups
	Custody Custody
	Disk    Disk
	// Upgrade is root's upgrade journal (/etc/varlatch/upgrade.json), nil
	// for none; UpgradeErr one that cannot be read.
	Upgrade    *upgradejournal.Journal
	UpgradeErr error
	// RestoreHeld is a restore's hold; Maintenance a maintenance gate.
	RestoreHeld bool
	Maintenance bool
	// WindowOpen is whether a migration's rollback window is open;
	// WindowErr a migration journal that cannot be read.
	WindowOpen bool
	WindowErr  error
	// Helper is the web upgrade's host helper (systemd only).
	Helper Helper
}

// Input is everything Judge reads.
type Input struct {
	Now time.Time
	// Running is this varlatchd's release.
	Running string
	// Check is the release check's record, nil for none.
	Check *release.ReleaseCheck
	// Target is the verified target's record, nil for none; TargetErr one
	// that cannot be read.
	Target    *release.Target
	TargetErr error
	Host      Host
}

// Report is the judgement: the target the tab offers (nil when the check
// recorded none for the newer release), whether it is rollback-safe for
// this release (nil until it is verified), and the checklist (nil when no
// newer release is known).
type Report struct {
	Target       *release.Target
	RollbackSafe *bool
	Lines        []Line
}

// Newer is the newer release the check found, "" for none.
func Newer(check *release.ReleaseCheck, running string) string {
	if check == nil || check.LastSuccess == nil {
		return ""
	}
	if order, ok := release.CompareVersions(check.LastSuccess.Latest.Version, running); ok && order > 0 {
		return check.LastSuccess.Latest.Version
	}
	return ""
}

// Judge is the pre-flight.
func Judge(in Input) Report {
	newer := Newer(in.Check, in.Running)
	if newer == "" {
		return Report{}
	}
	var r Report
	if t := in.Target; t != nil && t.Version == newer {
		r.Target = t
		if t.Verified != nil {
			safe := t.Verified.Declaration().SafeFor(in.Running, in.Host.Schema)
			r.RollbackSafe = &safe
		}
	}
	r.Lines = []Line{
		checkLine(in, newer, r.Target),
		backupLine(in),
		custodyLine(in),
		diskLine(in),
		inTheWayLine(in, r.Target),
		rollbackLine(in, newer, r.Target),
	}
	if in.Host.Deployment == Systemd {
		r.Lines = append(r.Lines, helperLine(in))
	}
	return r
}

// All is whether the report offers one click: a checklist whose every line
// passes, the helper's among them (a systemd host).
func (r Report) All() bool {
	helper := false
	for _, l := range r.Lines {
		if l.Status != Pass {
			return false
		}
		helper = helper || l.ID == LineHelper
	}
	return helper && r.Target != nil && r.Target.Verified != nil
}

// Line 7: the host helper is installed, accepts requests, and its
// heartbeat comes from the last release check.
func helperLine(in Input) Line {
	l := Line{ID: LineHelper, Title: "The host helper is installed and answered at the last release check"}
	enable := "To upgrade from here, install it on the host: sudo varlatch upgrade --enable-web (docs: Upgrading from the web app). Or upgrade with the commands below."
	h := in.Host.Helper
	switch {
	case h.Err != nil:
		l.Status, l.Detail, l.Remedy = Unknown, "Its record cannot be read: "+h.Err.Error(), "Run sudo varlatch upgrade --enable-web again"
	case !h.Present:
		l.Status, l.Detail, l.Remedy = Fail, "The host helper is not installed: this installation shows upgrade commands only", enable
	case !h.Enabled:
		l.Status, l.Detail, l.Remedy = Fail, "The host helper was turned off (sudo varlatch upgrade --disable-web)", enable
	case in.Now.Sub(h.At) > CheckMaxAge:
		l.Status, l.Detail, l.Remedy = Fail, "The host helper last answered "+Ago(in.Now, h.At), "Run sudo systemctl enable --now varlatch-release-check.timer (or sudo varlatch upgrade --enable-web again)"
	default:
		attempt, ok := time.Time{}, false
		if in.Check != nil {
			attempt, ok = parse(in.Check.LastAttempt.CheckedAt)
		}
		if ok && h.At.Before(attempt.Add(-HeartbeatSlack)) {
			l.Status, l.Detail, l.Remedy = Fail, "The last release check ("+Ago(in.Now, attempt)+") ran without the host helper, which last answered "+Ago(in.Now, h.At),
				"Run the release check through the helper's timer: sudo systemctl start varlatch-release-check.service"
			return l
		}
		l.Status, l.Detail = Pass, "Version "+h.Version+", last answered "+Ago(in.Now, h.At)
	}
	return l
}

// command is a host command as this installation runs it.
func command(d Deployment, cmd string) string {
	if d == Image {
		return "docker exec <container> " + cmd
	}
	return "sudo " + cmd
}

// Ago is how long before now t is, in words: "3 days ago".
func Ago(now, t time.Time) string {
	d := now.Sub(t)
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit + " ago"
		}
		return fmt.Sprintf("%d %ss ago", n, unit)
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int64(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int64(d/time.Hour), "hour")
	}
	return plural(int64(d/(24*time.Hour)), "day")
}

func parse(at string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, at)
	return t, err == nil
}

// failureText is the release check's failures, as the tab words them.
var failureText = map[string]string{
	"unreachable":     "GitHub could not be reached",
	"rate-limited":    "GitHub's rate limit was reached",
	"not-found":       "the repository has no published release",
	"invalid-answer":  "GitHub's answer was not a release",
	"not-verified":    "its SHA256SUMS is NOT signed by the release workflow for its tag, or a file does not match it: do not install it, and verify the release by hand",
	"invalid-release": "its release.json or varlatchd-image.txt is not this release's",
}

// targetFailureText is the target's failures, which overlap the check's.
func targetFailureText(f string) string {
	if f == "not-found" {
		return "a file the verification needs is missing from the release"
	}
	if t, ok := failureText[f]; ok {
		return t
	}
	return f
}

// Line 1: the host's release check ran in the last 36 hours and verified
// the target.
func checkLine(in Input, newer string, target *release.Target) Line {
	l := Line{ID: LineReleaseCheck, Title: "The host's release check ran in the last 36 hours and verified " + newer}
	again := "Run it again: " + command(in.Host.Deployment, "varlatch upgrade --check")
	schedule := "Schedule it on the host: install the release check's timer and service units, or its cron line, from Upgrading (Scheduling the release check), then run " +
		command(in.Host.Deployment, "varlatch upgrade --check") + " once"
	if in.Host.Deployment == Image {
		schedule = "Schedule " + command(Image, "varlatch upgrade --check") + " on the Docker host (a timer or a cron line, Upgrading: Scheduling the release check), then run it once"
	}
	attempt, ok := time.Time{}, false
	if in.Check != nil {
		attempt, ok = parse(in.Check.LastAttempt.CheckedAt)
	}
	switch {
	case in.Check == nil || !ok:
		l.Status, l.Detail, l.Remedy = Fail, "The release check has never run on this host.", schedule
	case in.Now.Sub(attempt) > CheckMaxAge:
		l.Status, l.Detail, l.Remedy = Fail, "The release check last ran "+Ago(in.Now, attempt)+".", schedule
	case in.Check.LastAttempt.Failed != nil:
		l.Status, l.Detail, l.Remedy = Fail, "The last release check, "+Ago(in.Now, attempt)+", failed: "+failureText[*in.Check.LastAttempt.Failed]+".", again
	case in.TargetErr != nil:
		l.Status, l.Detail, l.Remedy = Fail, "The record of the release check's verification cannot be read.", again
	case target == nil:
		l.Status, l.Detail = Fail, "The release check found "+newer+" but recorded no verification of it (a varlatch before this release ran it)."
		l.Remedy = again + ", with the varlatch installed beside this varlatchd"
	case target.Failed != nil:
		l.Status, l.Detail = Fail, "The release check could not verify "+newer+": "+targetFailureText(*target.Failed)+"."
		l.Remedy = again
		if *target.Failed == "not-verified" {
			l.Remedy = "Verifying a release shows how to check it by hand; report it if it does not verify"
		}
	default:
		verified, vok := parse(target.CheckedAt)
		if !vok || in.Now.Sub(verified) > CheckMaxAge {
			l.Status, l.Detail, l.Remedy = Fail, "The release check last verified "+newer+" "+Ago(in.Now, verified)+".", again
			break
		}
		l.Status = Pass
		l.Detail = "It ran " + Ago(in.Now, attempt) + " and verified " + newer + "'s signed SHA256SUMS, release.json and image."
	}
	return l
}

// Line 2: a backup destination is configured, and its last delivery
// succeeded in the last 24 hours.
func backupLine(in Input) Line {
	b := in.Host.Backups
	d := in.Host.Deployment
	l := Line{ID: LineBackup, Title: "A backup destination is configured, and its last delivery succeeded in the last 24 hours"}
	run := command(d, adminCommand(d, "admin backup run"))
	switch {
	case b.Destination == "":
		l.Status, l.Detail = Fail, "No backup destination is configured (backup_destination)."
		l.Remedy = "Configure one, your own S3-compatible bucket or B2 (Backup and recovery: S3-compatible destinations), then restart varlatchd and run " + run
	case b.Err != nil:
		l.Status, l.Detail = Unknown, "The backup status cannot be read: "+b.Err.Error()+"."
	case b.Last.IsZero():
		l.Status, l.Detail, l.Remedy = Fail, "No backup has been taken yet.", "Run "+run
	case b.Delivered.IsZero():
		l.Status, l.Detail = Fail, "The last backup, "+Ago(in.Now, b.Last)+", was not delivered to "+b.Destination+"."
		l.Remedy = command(d, adminCommand(d, "admin backup test-bucket")) + " says why; then run " + run
	case in.Now.Sub(b.Delivered) > DeliveryMaxAge:
		l.Status, l.Detail, l.Remedy = Fail, "The last delivery to "+b.Destination+" was "+Ago(in.Now, b.Delivered)+".", "Run "+run
	default:
		l.Status, l.Detail = Pass, "The last backup was delivered to "+b.Destination+" "+Ago(in.Now, b.Delivered)+"."
	}
	return l
}

// adminCommand is a backup or restore command: the host's varlatch runs
// it on a systemd host, varlatchd in the container.
func adminCommand(d Deployment, cmd string) string {
	if d == Image {
		return "varlatchd " + cmd
	}
	return "varlatch " + cmd
}

// Line 3: both keys have a Custody Attestation.
func custodyLine(in Input) Line {
	c := in.Host.Custody
	l := Line{ID: LineCustody, Title: "Both keys have a Custody Attestation"}
	var missing []string
	if !c.RootKEK {
		missing = append(missing, fmt.Sprintf("the Root KEK (version %d)", c.RootKEKVersion))
	}
	if !c.BackupKey {
		missing = append(missing, "the Backup Encryption Key")
	}
	switch {
	case c.Err != nil:
		l.Status, l.Detail = Unknown, "The Custody Attestations cannot be read: "+c.Err.Error()+"."
	case len(missing) > 0:
		has := "has"
		if len(missing) > 1 {
			has = "have"
		}
		text := strings.Join(missing, " and ")
		l.Status, l.Detail = Fail, strings.ToUpper(text[:1])+text[1:]+" "+has+" no Custody Attestation: without a copy off the host, a backup helps nobody."
		l.Remedy = "Keep a copy of each key off the host, then record it: " + command(in.Host.Deployment, "varlatchd admin custody attest --key <root-kek|backup-key> --method <copy|passphrase-escrow|shamir-split>")
	default:
		l.Status, l.Detail = Pass, "Both keys have a Custody Attestation."
	}
	return l
}

// Line 4: free space for the snapshot and the database copy, about twice
// the database.
func diskLine(in Input) Line {
	k := in.Host.Disk
	l := Line{ID: LineDisk, Title: "Free space for the snapshot and the database copy"}
	if k.Err != nil {
		l.Status, l.Detail = Unknown, "The data directory's free space cannot be read: "+k.Err.Error()+"."
		return l
	}
	need := 2*uint64(k.Database) + FreeMargin
	l.Detail = fmt.Sprintf("%s free; the database is %s, and an upgrade needs about twice that (the snapshot and the copy, plus %s).", size(k.Free), size(uint64(k.Database)), size(FreeMargin))
	if k.Free < need {
		l.Status, l.Remedy = Fail, "Free space on the data directory's filesystem, or grow it"
		return l
	}
	l.Status = Pass
	return l
}

func size(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", n>>10)
	}
}

// Line 5: no upgrade, rollback, restore hold, maintenance or rollback
// window in the way.
func inTheWayLine(in Input, target *release.Target) Line {
	h := in.Host
	l := Line{ID: LineInTheWay, Title: "No upgrade, rollback, restore hold, maintenance or rollback window in the way"}
	var details, remedies []string
	unknown := false
	switch j := h.Upgrade; {
	case h.UpgradeErr != nil:
		details = append(details, "The upgrade journal cannot be read.")
		remedies = append(remedies, "sudo varlatch upgrade says what to do with it")
	case j.Pending():
		what := "upgrade"
		if j.Kind == upgradejournal.Rollback {
			what = "rollback"
		}
		if j.State == upgradejournal.Failed {
			details = append(details, fmt.Sprintf("The %s from %s to %s could not be undone.", what, j.From, j.To))
		} else {
			details = append(details, fmt.Sprintf("The %s from %s to %s is not over (its last step is %q).", what, j.From, j.To, string(j.Step)))
		}
		remedies = append(remedies, "sudo varlatch upgrade finishes or undoes it")
	}
	if h.RestoreHeld {
		details = append(details, "This installation was restored from an archive and is held.")
		remedies = append(remedies, "Put right what changed since the archive, then run "+command(h.Deployment, adminCommand(h.Deployment, "admin restore resume")))
	}
	if h.Maintenance {
		details = append(details, "Installation maintenance is active.")
		remedies = append(remedies, command(h.Deployment, "varlatchd admin maintenance status")+" says whose it is")
	}
	if target != nil && target.Verified != nil && target.Verified.EndsRollbackWindow {
		switch {
		case h.WindowErr != nil:
			unknown = true
			details = append(details, "The migration journal cannot be read, so it is not known whether "+target.Version+" ends an open rollback window.")
		case h.WindowOpen:
			details = append(details, target.Version+" ends the migration's rollback window, which is still open.")
			remedies = append(remedies, "Upgrade from the host, which asks you to confirm it, or end the window first: sudo varlatch migrate --finish")
		}
	}
	switch {
	case len(remedies) > 0:
		l.Status = Fail
	case unknown:
		l.Status = Unknown
	default:
		l.Status, l.Detail = Pass, "No upgrade or rollback is under way, and nothing holds the installation."
		return l
	}
	l.Detail, l.Remedy = strings.Join(details, " "), strings.Join(remedies, "; ")
	return l
}

// Line 6: the target declares itself rollback-safe for the installed
// release (Decision 4), as `varlatch upgrade` judges it.
func rollbackLine(in Input, newer string, target *release.Target) Line {
	l := Line{ID: LineRollbackSafe, Title: newer + " is rollback-safe for " + in.Running}
	if target == nil || target.Verified == nil {
		l.Status, l.Detail = Unknown, "Not known until the release check verifies "+newer+"."
		return l
	}
	v := target.Verified
	d := v.Declaration()
	switch {
	case d.SafeFor(in.Running, in.Host.Schema):
		l.Status, l.Detail = Pass, newer+" declares itself rollback-safe for "+in.Running+", which opens the upgraded database: going back needs no restore."
	case v.Previous == nil || v.Previous.Version != in.Running:
		checked := "no earlier release"
		if v.Previous != nil {
			checked = v.Previous.Version
		}
		l.Status, l.Detail = Fail, newer+" was checked against "+checked+", not "+in.Running+": upgrade one release at a time."
		l.Remedy = "Upgrade one release at a time, oldest first: each step is rollback-safe where its release declares it"
	case !v.RollbackSafe:
		l.Status, l.Detail = Fail, newer+" does not declare itself rollback-safe for "+in.Running+": going back means restoring the pre-upgrade snapshot, which loses every change made after it."
		l.Remedy = "Read the release notes, and upgrade from the host, which asks you to confirm it"
	default:
		l.Status, l.Detail = Fail, fmt.Sprintf("Once upgraded, the database needs a varlatchd of schema %d or later, which %s (schema %d) is not: going back means restoring the pre-upgrade snapshot.", v.CompatibleFrom, in.Running, in.Host.Schema)
		l.Remedy = "Read the release notes, and upgrade from the host, which asks you to confirm it"
	}
	return l
}
