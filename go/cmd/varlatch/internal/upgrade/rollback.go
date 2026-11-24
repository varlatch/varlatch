// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// `varlatch upgrade --rollback` (ADR-0059 Decision 8; internal
// docs/design/go-step6.md, slice 6.6c): back to the release the last
// upgrade came from, with that release's kept binaries.
//
//   - Rollback-safe, on both counts: the upgrade's verified release.json
//     declared itself rollback-safe for the release returned to (the
//     declaration G6 checks; DeclaredRollbackSafe in the journal), and that
//     release's varlatchd opens the database as it is (`admin schema
//     status`). The binaries go back and the database stays, so every
//     change made since the upgrade is kept.
//   - Otherwise, either count failing: a schema the previous varlatchd
//     opens may still hold changes whose meaning it does not know, which
//     is what the declaration says. The pre-upgrade snapshot is restored (the previous
//     varlatchd's `admin backup restore`), so every change made since it is
//     lost. PlanRollback lists them first (`admin changes`: the audit
//     events since the snapshot, by type, no value), and the database the
//     rollback replaces is kept with the rollback, 30 days.
//
// A rollback is journaled as an upgrade is (Kind rollback, From the release
// it leaves, To the one it returns to), from the stop on, with the same
// steps, undo and recovery: it ends with the release it left serving after
// its checks, or the one it returns to. Undone, it leaves the upgrade's own
// record again, so it can be run again once what stopped it is put right.
//
// Before the stop it has checked all it can: the kept binaries are the ones
// the upgrade recorded, the snapshot too (root's copy, by its SHA-256), and
// it opens with the host's keys in the release returned to. After the stop
// it lists the changes again: what was made meanwhile is lost too.
//
// It changes nothing while the data directory holds a maintenance gate (a
// migration's barrier, a restore, a capture), or a migration that is not
// open or finished, or that switched after the upgrade began (the release
// and the snapshot it would return to are from before it).

// RollbackSince is the first release whose varlatch reads a rollback's
// journal, and whose varlatchd holds still while one is not over. The
// release returned to reads it (it finishes or undoes an interrupted
// rollback once its varlatch is back in place, and upgrades next). A member
// added to the journal later, written by a rollback, raises this.
const RollbackSince = journal.FormatSince

// ReturnsTo is whether a rollback may return to a release (RollbackSince).
func ReturnsTo(version string) bool {
	order, ok := release.CompareVersions(version, RollbackSince)
	return ok && order >= 0
}

// Changes are the audit events since a time, as `admin changes` counts
// them: never a value.
type Changes struct {
	Since  string           `json:"since"`
	Total  int64            `json:"total"`
	ByType map[string]int64 `json:"byType"`
	Latest []Change         `json:"latest"`
	// Revocations are the revocations, removals, rotations, replacements,
	// deletions and freezes the restore takes back (a revoked credential
	// works again): of RevocationsTotal, the newest.
	RevocationsTotal int64    `json:"revocationsTotal"`
	Revocations      []Change `json:"revocations"`
}

// Change is one audit event: its type, time, decision, Organization and,
// for a revocation, its resource (kinds and identifiers, never a value).
type Change struct {
	OccurredAt     string  `json:"occurredAt"`
	EventType      string  `json:"eventType"`
	Decision       string  `json:"decision"`
	OrganizationID *string `json:"organizationId"`
	Resource       *string `json:"resource,omitempty"`
}

// RollbackPlan is what a rollback would do; nothing has changed yet.
type RollbackPlan struct {
	// Last is the upgrade it rolls back.
	Last *journal.Journal
	// Safe: the database stays. Declared and Opens are the two counts it
	// needs (the release's declaration for the release returned to, and
	// that release's varlatchd opening the database); Rule says which
	// decided.
	Safe, Declared, Opens bool
	Rule                  string
	// Lost, when not Safe: the changes since the snapshot, which the
	// restore loses.
	Lost *Changes
	// Migration, of an installation that migrated: what the rollback
	// leaves of the migration's own rollback window, "" when it has none.
	Migration string
	// since is what Lost lists from.
	since string
}

// lostMargin reaches back before the snapshot's recorded time, so a change
// made while the archive was sealed is listed rather than lost unseen.
const lostMargin = time.Minute

// kindName names the change a journal records: an upgrade or a rollback.
func kindName(j *journal.Journal) string {
	if j.Kind == journal.Rollback {
		return "a rollback"
	}
	return "an upgrade"
}

// PlanRollback reads the journal and the host: the last upgrade must be
// done, its release must still be installed, and the previous release's
// kept binaries (and, unless the database stays, the snapshot) must be
// there, and be the ones the upgrade recorded. It refuses with why
// otherwise, and runs nothing it has not checked.
func (u *Upgrader) PlanRollback(ctx context.Context) (RollbackPlan, error) {
	last, err := journal.Read(u.configDir())
	switch {
	case err != nil:
		return RollbackPlan{}, err
	case last == nil:
		return RollbackPlan{}, errors.New("no upgrade is recorded on this host (" + filepath.Join(u.configDir(), journal.File) + "): there is nothing to roll back")
	case last.Pending():
		return RollbackPlan{}, fmt.Errorf("%s from %s to %s is not over (%s at step %q): run varlatch upgrade first to finish or undo it", kindName(last), last.From, last.To, last.State, last.Step)
	case last.Kind == journal.Rollback:
		// The upgrade it rolled back is no longer the last change. Going
		// back further is by hand.
		return RollbackPlan{}, fmt.Errorf("the last change was a rollback from %s to %s: there is no upgrade to roll back. To go back further, restore an archive (varlatchd admin backup restore)", last.From, last.To)
	case last.State == journal.Undone:
		return RollbackPlan{}, fmt.Errorf("the last upgrade, to %s, was undone and %s serves: there is nothing to roll back", last.To, last.From)
	case !ReturnsTo(last.From):
		return RollbackPlan{}, fmt.Errorf("%s's varlatch cannot read a rollback's journal (%s is the first that can), so it could neither finish an interrupted rollback nor upgrade after one. By hand, losing every change made since the upgrade:\n%s",
			last.From, RollbackSince, u.byHand(last))
	case last.Format == journal.FormatOne || last.Binaries == nil:
		return RollbackPlan{}, fmt.Errorf("the upgrade to %s was made by a varlatch that did not record its binaries' checksums: they are not run unchecked. By hand, losing every change made since the upgrade:\n%s", last.To, u.byHand(last))
	}
	if err := u.trusted(); err != nil {
		return RollbackPlan{}, err
	}
	migration, err := rollbackHost(last, u.now())
	if err != nil {
		return RollbackPlan{}, err
	}
	if sum, err := fileSum(u.varlatchd()); err != nil || sum != last.Binaries.To.Varlatchd {
		return RollbackPlan{}, fmt.Errorf("%s is not the varlatchd the upgrade to %s installed: a rollback returns only from that one", u.varlatchd(), last.To)
	}
	if err := u.bothKept(last); err != nil {
		return RollbackPlan{}, fmt.Errorf("there is no previous release to roll back to: %w", err)
	}
	prev, err := u.kept(last, last.From, "varlatchd")
	if err != nil {
		return RollbackPlan{}, err
	}
	out, err := u.admin(ctx, prev, "admin", "schema", "status", "--json")
	if err != nil {
		return RollbackPlan{}, fmt.Errorf("%s's varlatchd admin schema status: %v", last.From, err)
	}
	var st struct {
		Opens    bool   `json:"opens"`
		DataDir  string `json:"dataDir"`
		Database *struct {
			SchemaVersion int64 `json:"schemaVersion"`
		} `json:"database"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return RollbackPlan{}, fmt.Errorf("%s's varlatchd admin schema status gave no answer", last.From)
	}
	if st.DataDir != last.DataDir {
		return RollbackPlan{}, fmt.Errorf("%s names the data directory %s, and the upgrade was made in %s: a rollback returns only that one", u.ConfigPath, st.DataDir, last.DataDir)
	}
	if st.Database == nil {
		// A varlatchd started here would make an empty one.
		return RollbackPlan{}, fmt.Errorf("there is no database in %s: a rollback has nothing to keep. Put it back, or restore an archive (varlatchd admin backup restore)", last.DataDir)
	}
	plan := RollbackPlan{Last: last, Declared: last.DeclaredRollbackSafe, Opens: st.Opens, Migration: migration}
	plan.Safe = plan.Declared && plan.Opens
	switch {
	case plan.Safe:
		plan.Rule = fmt.Sprintf("%s's release.json declares it rollback-safe for %s, and %s opens the database as it is: the database stays", last.To, last.From, last.From)
	case !plan.Declared && plan.Opens:
		plan.Rule = fmt.Sprintf("%s's release.json does not declare it rollback-safe for %s: though %s opens the database, it may hold changes %s does not know the meaning of, so the snapshot is restored", last.To, last.From, last.From, last.From)
	case plan.Declared:
		plan.Rule = fmt.Sprintf("%s's release.json declares it rollback-safe for %s, but %s cannot open the database as it is: the snapshot is restored", last.To, last.From, last.From)
	default:
		plan.Rule = fmt.Sprintf("%s's release.json does not declare it rollback-safe for %s, and %s cannot open the database as it is: the snapshot is restored", last.To, last.From, last.From)
	}
	if err := u.rollbackSpace(ctx, last, plan.Safe); err != nil {
		return RollbackPlan{}, err
	}
	if plan.Safe {
		return plan, nil
	}
	if err := u.snapshotStands(last); err != nil {
		return RollbackPlan{}, fmt.Errorf("%s; but %w", plan.Rule, err)
	}
	// The archive opens, with the host's keys, in the release that restores
	// it: what would fail after the stop fails now. (And before the list is
	// made, so that little comes between it and the stop.)
	if _, err := u.admin(ctx, prev, "admin", "backup", "restore", "--check", "--in", last.Snapshot); err != nil {
		return RollbackPlan{}, fmt.Errorf("%s; but the pre-upgrade snapshot does not restore: %w", plan.Rule, err)
	}
	at, err := time.Parse(time.RFC3339, last.SnapshotAt)
	if err != nil {
		return RollbackPlan{}, errors.New("the upgrade journal does not say when the snapshot was taken")
	}
	plan.since = at.Add(-lostMargin).UTC().Format(time.RFC3339)
	if plan.Lost, err = u.changes(ctx, plan.since); err != nil {
		return RollbackPlan{}, err
	}
	return plan, nil
}

// bothKept checks that both releases' binaries are kept: the one a rollback
// returns to, and the one its undo does.
func (u *Upgrader) bothKept(last *journal.Journal) error {
	for _, version := range []string{last.From, last.To} {
		for _, name := range binaryNames {
			if _, err := u.kept(last, version, name); err != nil {
				return fmt.Errorf("%s's %s: %w", version, name, err)
			}
		}
	}
	return nil
}

// byHand are the steps back for a release a rollback does not return to,
// as they are run.
func (u *Upgrader) byHand(last *journal.Journal) string {
	kept := filepath.Join(last.Releases, last.From)
	uid, gid, _, err := ownerToBe(last.DataDir)
	owner := fmt.Sprintf("%d:%d", uid, gid)
	if err != nil {
		owner = "<its owner>"
	}
	lines := []string{
		"sudo systemctl stop varlatchd",
		fmt.Sprintf("sudo install -m 755 %s %s %s", shellWord(filepath.Join(kept, "varlatch")), shellWord(filepath.Join(kept, "varlatchd")), shellWord(u.BinDir)),
		fmt.Sprintf("sudo %s admin backup restore --in %s --config %s", shellWord(u.varlatchd()), shellWord(last.Snapshot), shellWord(u.ConfigPath)),
		// Its restore runs as root and leaves root's files.
		fmt.Sprintf("sudo chown -R --no-dereference --from=0 %s %s", owner, shellWord(last.DataDir)),
	}
	if last.Format != journal.FormatOne {
		journalPath := filepath.Join(u.configDir(), journal.File)
		lines = append(lines, fmt.Sprintf("sudo mv %s %s", shellWord(journalPath), shellWord(filepath.Join(u.configDir(), "upgrade-"+last.ID+".json"))))
	}
	lines = append(lines, "sudo systemctl start varlatchd")
	return "  " + strings.Join(lines, "\n  ")
}

// shellWord is s as one word of a shell's.
func shellWord(s string) string {
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@%", r))
	}) < 0 && s != "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// snapshotStands checks that the snapshot is there and is the one the
// upgrade recorded, where only root changes it.
func (u *Upgrader) snapshotStands(last *journal.Journal) error {
	if last.Snapshot == "" || !exists(last.Snapshot) {
		return fmt.Errorf("the pre-upgrade snapshot (%s) is gone: a rollback would have nothing to restore", last.Snapshot)
	}
	if err := rootOwned(last.Snapshot); err != nil {
		return err
	}
	sum, err := fileSum(last.Snapshot)
	if err != nil {
		return err
	}
	if sum != last.SnapshotSHA256 || last.SnapshotSHA256 == "" {
		return fmt.Errorf("the pre-upgrade snapshot %s is not the one the upgrade recorded (SHA-256 %s, not %s)", last.Snapshot, sum, last.SnapshotSHA256)
	}
	return nil
}

// changes are the installed varlatchd's `admin changes` since a time,
// varlatchd running or not.
func (u *Upgrader) changes(ctx context.Context, since string) (*Changes, error) {
	out, err := u.admin(ctx, u.varlatchd(), "admin", "changes", "--since", since, "--json")
	if err != nil {
		return nil, fmt.Errorf("listing the changes since the snapshot: %v", err)
	}
	var lost Changes
	if err := json.Unmarshal(out, &lost); err != nil {
		return nil, errors.New("varlatchd admin changes gave no list")
	}
	return &lost, nil
}

// rollbackHost is whether the installation in last's data directory is one
// a rollback may touch: no maintenance gate stands, and a migration it
// made is one the upgrade came after (migrate.BeforeUpgrade, whose answer
// about the migration's rollback window it returns).
func rollbackHost(last *journal.Journal, now time.Time) (string, error) {
	gate, err := backup.ReadGate(last.DataDir)
	switch {
	case err != nil:
		return "", fmt.Errorf("the maintenance gate %s: %v", filepath.Join(last.DataDir, backup.GateFile), err)
	case gate != nil && gate.Kind == "migration":
		return "", fmt.Errorf("a migration's gate stands in %s (%s): finish or abort the migration first (varlatch migrate --status)", last.DataDir, backup.GateFile)
	case gate.Active(now):
		return "", fmt.Errorf("a maintenance gate stands in %s (%s, kind %s): end it first (varlatchd admin maintenance status)", last.DataDir, backup.GateFile, gate.Kind)
	}
	if Held(last.DataDir) {
		return "", fmt.Errorf("this installation was restored from an archive since the upgrade and is held (%s): end the hold first (varlatch admin restore resume)", holdFile)
	}
	began, err := time.Parse(time.RFC3339, last.StartedAt)
	if err != nil {
		return "", errors.New("the upgrade journal does not say when the upgrade began")
	}
	return migrate.BeforeUpgrade(last.DataDir, last.To, began, now)
}

// Held is whether the installation is held after a restore: it serves, and
// its operator ends the hold (varlatch admin restore resume).
func Held(dataDir string) bool { return exists(filepath.Join(dataDir, holdFile)) }

// ErrDeclined is a rollback whose losses, grown since they were accepted,
// were not.
var ErrDeclined = errors.New("more changes were made since the list was shown, and their loss was not accepted")

// Rollback runs plan: back to its upgrade's previous release. grown is
// asked, after the stop, when the changes a restore loses are more than the
// plan's: whether to go on. Its error is an *Error unless a crash point
// stopped it.
func (u *Upgrader) Rollback(ctx context.Context, plan RollbackPlan, grown func(*Changes) (bool, error)) (*journal.Journal, error) {
	unlock, err := lock(u.configDir())
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	defer unlock()
	last := plan.Last
	refuse := func(err error) (*journal.Journal, error) {
		return nil, &Error{Message: err.Error() + "; nothing was changed"}
	}
	if now, err := journal.Read(u.configDir()); err != nil || now == nil || now.ID != last.ID || now.State != journal.Done || now.Kind != journal.Upgrade {
		return refuse(errors.New("the upgrade journal changed since the rollback was planned"))
	}
	// Again, now that it begins: the prompt may have waited.
	if _, err := rollbackHost(last, u.now()); err != nil {
		return refuse(err)
	}
	if err := u.bothKept(last); err != nil {
		return refuse(err)
	}
	if err := u.rollbackSpace(ctx, last, plan.Safe); err != nil {
		return refuse(err)
	}
	if !plan.Safe {
		if err := u.snapshotStands(last); err != nil {
			return refuse(err)
		}
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return refuse(err)
	}
	upgraded := *last
	j := &journal.Journal{
		ID: hex.EncodeToString(id), Kind: journal.Rollback, Upgraded: &upgraded,
		From: last.To, To: last.From, FromSchema: last.ToSchema, ToSchema: last.FromSchema,
		RollbackSafe: plan.Safe, RollbackRule: plan.Rule, State: journal.InProgress, Step: journal.Verified, StartedAt: u.now().UTC().Format(time.RFC3339),
		BinDir: u.BinDir, Releases: last.Releases, DataDir: last.DataDir,
		Binaries: &journal.Binaries{From: last.Binaries.To, To: last.Binaries.From},
		Snapshot: last.Snapshot, SnapshotSHA256: last.SnapshotSHA256, SnapshotAt: last.SnapshotAt, SnapshotArchive: last.SnapshotArchive, SnapshotBytes: last.SnapshotBytes,
	}
	j.Work = filepath.Join(j.DataDir, "upgrades", j.ID)
	if _, err := u.data(ctx, dataOp{Op: "begin", DataDir: j.DataDir, ID: j.ID}); err != nil {
		if errors.Is(err, errKilled) {
			return nil, err
		}
		return refuse(err)
	}
	// The rollback's record takes the upgrade's place here, with the stop:
	// until then nothing of the host is changed.
	err = u.rollbackSteps(ctx, j, plan, grown)
	switch {
	case err == nil:
		return j, nil
	case errors.Is(err, errKilled):
		return j, err
	case j.Reached(journal.Checked):
		return j, &Error{Message: u.unfinished(j, err), Journal: j}
	case !j.Reached(journal.Stopping):
		return refuse(fmt.Errorf("cannot write the upgrade journal in %s: %w", u.configDir(), err))
	}
	reason := err.Error()
	if uerr := u.undo(ctx, j, reason); uerr != nil {
		if errors.Is(uerr, errKilled) {
			return j, uerr
		}
		return j, &Error{Message: uerr.Error(), Journal: j}
	}
	return j, &Error{Message: fmt.Sprintf("the rollback to %s did not complete (%s); it was undone: %s serves, on its database as it was. It can be run again", j.To, reason, j.From), Journal: j}
}

func (u *Upgrader) rollbackSteps(ctx context.Context, j *journal.Journal, plan RollbackPlan, grown func(*Changes) (bool, error)) error {
	if err := u.reach(j, journal.Stopping); err != nil {
		return err
	}
	if err := u.Service.Stop(ctx); err != nil {
		return fmt.Errorf("stopping varlatchd: %w", err)
	}
	if err := u.point("stop:done"); err != nil {
		return err
	}
	if err := u.reach(j, journal.Stopped); err != nil {
		return err
	}
	u.logf("Stopped varlatchd %s.", j.From)
	if !j.RollbackSafe {
		// Nothing changes the database any more: what the restore loses.
		now, err := u.changes(ctx, plan.since)
		if err != nil {
			return err
		}
		if now.Total > plan.Lost.Total || now.RevocationsTotal > plan.Lost.RevocationsTotal {
			ok := false
			if grown != nil {
				if ok, err = grown(now); err != nil {
					return err
				}
			}
			if !ok {
				return ErrDeclined
			}
		}
	}
	if err := u.reach(j, journal.Prepared); err != nil {
		return err
	}
	if !j.RollbackSafe {
		if _, err := u.data(ctx, dataOp{Op: "keep-original", DataDir: j.DataDir, ID: j.ID}); err != nil {
			return fmt.Errorf("keeping the database: %w", err)
		}
	}
	if err := u.reach(j, journal.Kept); err != nil {
		return err
	}
	if err := u.install(j, j.To, j.Binaries.To, binaryNames...); err != nil {
		return fmt.Errorf("putting %s's binaries back: %w", j.To, err)
	}
	if err := u.reach(j, journal.Installed); err != nil {
		return err
	}
	if !j.RollbackSafe {
		if err := u.snapshotStands(j); err != nil {
			return err
		}
		if _, err := u.admin(ctx, u.varlatchd(), "admin", "backup", "restore", "--in", j.Snapshot); err != nil {
			return fmt.Errorf("restoring the pre-upgrade snapshot: %w", err)
		}
		if err := u.point("rollback:restored"); err != nil {
			return err
		}
		u.logf("Restored the pre-upgrade snapshot with %s; the database it replaced is kept in %s.", j.To, filepath.Join(j.Work, originalDir))
	}
	if err := u.reach(j, journal.Swapped); err != nil {
		return err
	}
	if err := u.start(ctx, j, j.To); err != nil {
		return err
	}
	if err := u.reachStarted(j); err != nil {
		return err
	}
	if err := u.check(ctx, j.To, j.ToSchema); err != nil {
		return fmt.Errorf("the health checks of %s: %w", j.To, err)
	}
	if err := u.reach(j, journal.Checked); err != nil {
		return err
	}
	return u.promote(ctx, j)
}

// rollbackSpace refuses a rollback the disks cannot hold: the restored
// database twice (the archive's opened content, and the copy put in place),
// and, where the file system has no hard links, the one it replaces; and the
// binaries, written beside their places.
func (u *Upgrader) rollbackSpace(ctx context.Context, last *journal.Journal, safe bool) error {
	var binaries int64
	for _, name := range binaryNames {
		if info, err := os.Stat(filepath.Join(last.Releases, last.From, name)); err == nil {
			binaries += info.Size()
		}
	}
	needs := []need{{u.BinDir, binaries, "the previous release's binaries"}}
	if !safe {
		size, err := u.data(ctx, dataOp{Op: "size", DataDir: last.DataDir})
		if err != nil {
			return err
		}
		restored := last.SnapshotBytes
		if restored <= 0 {
			restored = size.Bytes
		}
		needs = append(needs, need{last.DataDir, size.Bytes + 2*restored, "the restored database, opened and put in place, and a copy of the one it replaces"})
	}
	return u.spaceFor("the rollback", needs)
}
