// SPDX-License-Identifier: AGPL-3.0-or-later

package upgradecheck

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
)

var now = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// checked is a release check that ran at, and found version.
func checked(at time.Time, version string) *release.ReleaseCheck {
	rc := &release.ReleaseCheck{}
	rc.LastAttempt.CheckedAt, rc.LastAttempt.Repo = iso(at), release.Repository
	rc.LastSuccess = &struct {
		CheckedAt  string         `json:"checkedAt"`
		Repo       string         `json:"repo"`
		Latest     release.Latest `json:"latest"`
		ReleaseSet bool           `json:"releaseSet"`
	}{iso(at), release.Repository, release.Latest{Version: version}, true}
	return rc
}

func target(at time.Time, previous string) *release.Target {
	return &release.Target{Version: "0.52.0", CheckedAt: iso(at), Verified: &release.VerifiedTarget{
		SchemaVersion: 8, CompatibleFrom: 7, RollbackSafe: true, Previous: &release.Previous{Version: previous, SchemaVersion: 7},
		Image: "ghcr.io/varlatch/varlatchd:0.52.0@sha256:" + strings.Repeat("0123456789abcdef", 4),
	}}
}

// ready is an installation on 0.51.0 (schema 7) that passes every line for
// 0.52.0.
func ready() Input {
	return Input{Now: now, Running: "0.51.0", Check: checked(now.Add(-3*time.Hour), "0.52.0"), Target: target(now.Add(-3*time.Hour), "0.51.0"),
		Host: Host{Deployment: Systemd, Schema: 7,
			Backups: Backups{Destination: "offsite", Last: now.Add(-2 * time.Hour), Delivered: now.Add(-2 * time.Hour)},
			Custody: Custody{RootKEKVersion: 1, RootKEK: true, BackupKey: true},
			Disk:    Disk{Free: 10 << 30, Database: 100 << 20}}}
}

func line(t *testing.T, r Report, id string) Line {
	t.Helper()
	for _, l := range r.Lines {
		if l.ID == id {
			return l
		}
	}
	t.Fatalf("no line %s in %+v", id, r.Lines)
	return Line{}
}

func TestEveryLinePasses(t *testing.T) {
	r := Judge(ready())
	if r.Target == nil || r.RollbackSafe == nil || !*r.RollbackSafe || len(r.Lines) != 6 {
		t.Fatalf("%+v", r)
	}
	for _, l := range r.Lines {
		if l.Status != Pass || l.Remedy != "" {
			t.Errorf("%s: %s %q %q", l.ID, l.Status, l.Detail, l.Remedy)
		}
	}
	if got := line(t, r, LineRollbackSafe).Detail; got != "0.52.0 declares itself rollback-safe for 0.51.0, which opens the upgraded database: going back needs no restore." {
		t.Errorf("one release's step: %q", got)
	}
}

func TestNoChecklistWithoutANewerRelease(t *testing.T) {
	in := ready()
	in.Check = checked(now, "0.51.0")
	if r := Judge(in); r.Lines != nil || r.Target != nil || r.RollbackSafe != nil {
		t.Errorf("nothing newer: %+v", r)
	}
	in.Check = nil
	if r := Judge(in); r.Lines != nil {
		t.Errorf("never checked: %+v", r)
	}
}

// Decision 4: a jump that skips releases is never rollback-safe, even when
// the release declares itself so for the one before it.
func TestASkippedReleaseFails(t *testing.T) {
	in := ready()
	in.Target = target(now.Add(-time.Hour), "0.51.1")
	r := Judge(in)
	l := line(t, r, LineRollbackSafe)
	if l.Status != Fail || l.Detail != "0.52.0 was checked against 0.51.1, not 0.51.0: upgrade one release at a time." || !strings.Contains(l.Remedy, "one release at a time") {
		t.Errorf("a jump: %+v", l)
	}
	if r.RollbackSafe == nil || *r.RollbackSafe {
		t.Errorf("the judgement of a jump: %v", r.RollbackSafe)
	}

	in = ready()
	in.Target.Verified.RollbackSafe, in.Target.Verified.CompatibleFrom = false, 8
	if l := line(t, Judge(in), LineRollbackSafe); l.Status != Fail || !strings.Contains(l.Detail, "does not declare itself rollback-safe for 0.51.0") {
		t.Errorf("not declared: %+v", l)
	}
	in = ready()
	in.Host.Schema = 6
	if l := line(t, Judge(in), LineRollbackSafe); l.Status != Fail || !strings.Contains(l.Detail, "schema 7 or later, which 0.51.0 (schema 6) is not") {
		t.Errorf("a schema below compatibleFrom: %+v", l)
	}
	in = ready()
	in.Target = nil
	if l := line(t, Judge(in), LineRollbackSafe); l.Status != Unknown {
		t.Errorf("no target: %+v", l)
	}
}

// Decision 8, line 1: a check that never ran, or ran 36 hours ago or more,
// fails, and says how to fix it.
func TestStaleAndNeverRunChecks(t *testing.T) {
	in := ready()
	in.Check.LastAttempt.CheckedAt = iso(now.Add(-72 * time.Hour))
	l := line(t, Judge(in), LineReleaseCheck)
	if l.Status != Fail || l.Detail != "The release check last ran 3 days ago." || !strings.Contains(l.Remedy, "timer and service units, or its cron line") {
		t.Errorf("3 days ago: %+v", l)
	}
	in.Check.LastAttempt.CheckedAt = iso(now.Add(-37 * time.Hour))
	if l := line(t, Judge(in), LineReleaseCheck); l.Status != Fail || l.Detail != "The release check last ran 37 hours ago." {
		t.Errorf("37 hours ago: %+v", l)
	}
	in.Host.Deployment = Image
	if l := line(t, Judge(in), LineReleaseCheck); !strings.Contains(l.Remedy, "docker exec <container> varlatch upgrade --check on the Docker host") {
		t.Errorf("in the image: %+v", l)
	}

	// Never run: the record has no attempt.
	in = ready()
	in.Check.LastAttempt.CheckedAt = ""
	if l := line(t, Judge(in), LineReleaseCheck); l.Status != Fail || l.Detail != "The release check has never run on this host." {
		t.Errorf("never run: %+v", l)
	}

	// Recent, but the last attempt failed, or verified nothing, or
	// verified another release, or failed to verify.
	in = ready()
	failed := "unreachable"
	in.Check.LastAttempt.Failed = &failed
	if l := line(t, Judge(in), LineReleaseCheck); l.Status != Fail || l.Detail != "The last release check, 3 hours ago, failed: GitHub could not be reached." {
		t.Errorf("failed: %+v", l)
	}
	in = ready()
	in.Target = nil
	if l := line(t, Judge(in), LineReleaseCheck); l.Status != Fail || !strings.Contains(l.Detail, "recorded no verification") {
		t.Errorf("no target: %+v", l)
	}
	in.Target = target(now, "0.51.0")
	in.Target.Version = "0.51.5"
	if r := Judge(in); line(t, r, LineReleaseCheck).Status != Fail || r.Target != nil {
		t.Errorf("another release's target: %+v", r)
	}
	in = ready()
	notVerified := "not-verified"
	in.Target.Verified, in.Target.Failed = nil, &notVerified
	if l := line(t, Judge(in), LineReleaseCheck); l.Status != Fail || !strings.Contains(l.Detail, "is NOT signed by the release workflow") || !strings.Contains(l.Remedy, "Verifying a release") {
		t.Errorf("not verified: %+v", l)
	}
	in = ready()
	in.TargetErr = errors.New("unreadable")
	if l := line(t, Judge(in), LineReleaseCheck); l.Status != Fail {
		t.Errorf("an unreadable target: %+v", l)
	}
}

func TestBackupCustodyAndDisk(t *testing.T) {
	in := ready()
	in.Host.Backups.Destination = ""
	if l := line(t, Judge(in), LineBackup); l.Status != Fail || l.Detail != "No backup destination is configured (backup_destination)." || !strings.Contains(l.Remedy, "S3-compatible") {
		t.Errorf("no destination: %+v", l)
	}
	in = ready()
	in.Host.Backups.Delivered = time.Time{}
	if l := line(t, Judge(in), LineBackup); l.Status != Fail || l.Detail != "The last backup, 2 hours ago, was not delivered to offsite." || !strings.Contains(l.Remedy, "sudo varlatch admin backup test-bucket") {
		t.Errorf("not delivered: %+v", l)
	}
	in = ready()
	in.Host.Backups.Last, in.Host.Backups.Delivered = now.Add(-50*time.Hour), now.Add(-50*time.Hour)
	if l := line(t, Judge(in), LineBackup); l.Status != Fail || l.Detail != "The last delivery to offsite was 2 days ago." {
		t.Errorf("an old delivery: %+v", l)
	}
	in = ready()
	in.Host.Backups.Last = time.Time{}
	if l := line(t, Judge(in), LineBackup); l.Status != Fail || l.Detail != "No backup has been taken yet." {
		t.Errorf("no backup: %+v", l)
	}

	in = ready()
	in.Host.Custody.BackupKey = false
	if l := line(t, Judge(in), LineCustody); l.Status != Fail || !strings.HasPrefix(l.Detail, "The Backup Encryption Key has no Custody Attestation") {
		t.Errorf("one key: %+v", l)
	}
	in.Host.Custody.RootKEK = false
	if l := line(t, Judge(in), LineCustody); l.Status != Fail || !strings.HasPrefix(l.Detail, "The Root KEK (version 1) and the Backup Encryption Key have no") {
		t.Errorf("both keys: %+v", l)
	}

	in = ready()
	in.Host.Disk = Disk{Free: 200 << 20, Database: 100 << 20}
	if l := line(t, Judge(in), LineDisk); l.Status != Fail || !strings.Contains(l.Detail, "about twice that") {
		t.Errorf("too little space: %+v", l)
	}
	in.Host.Disk = Disk{Err: errors.New("not measured on this system")}
	if l := line(t, Judge(in), LineDisk); l.Status != Unknown {
		t.Errorf("unmeasured: %+v", l)
	}
}

func TestInTheWay(t *testing.T) {
	in := ready()
	in.Host.Upgrade = &upgradejournal.Journal{ID: "a", From: "0.50.2", To: "0.51.0", State: upgradejournal.InProgress, Step: upgradejournal.Swapped}
	if l := line(t, Judge(in), LineInTheWay); l.Status != Fail || l.Detail != `The upgrade from 0.50.2 to 0.51.0 is not over (its last step is "swapped").` {
		t.Errorf("an upgrade under way: %+v", l)
	}
	in.Host.Upgrade.State = upgradejournal.Done
	if l := line(t, Judge(in), LineInTheWay); l.Status != Pass {
		t.Errorf("an upgrade over: %+v", l)
	}
	in = ready()
	in.Host.RestoreHeld, in.Host.Maintenance = true, true
	if l := line(t, Judge(in), LineInTheWay); l.Status != Fail || !strings.Contains(l.Detail, "restored from an archive and is held") || !strings.Contains(l.Detail, "maintenance is active") {
		t.Errorf("held: %+v", l)
	}
	in = ready()
	in.Target.Verified.EndsRollbackWindow, in.Host.WindowOpen = true, true
	if l := line(t, Judge(in), LineInTheWay); l.Status != Fail || !strings.Contains(l.Detail, "ends the migration's rollback window") || !strings.Contains(l.Remedy, "varlatch migrate --finish") {
		t.Errorf("a window: %+v", l)
	}
	in.Host.WindowOpen = false
	if l := line(t, Judge(in), LineInTheWay); l.Status != Pass {
		t.Errorf("no window open: %+v", l)
	}
}

func TestAgo(t *testing.T) {
	for want, d := range map[string]time.Duration{"just now": 10 * time.Second, "1 minute ago": time.Minute, "5 hours ago": 5 * time.Hour, "47 hours ago": 47 * time.Hour, "3 days ago": 72 * time.Hour} {
		if got := Ago(now, now.Add(-d)); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}
