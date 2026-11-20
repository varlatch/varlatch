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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
// it leaves, To the one it returns to), with the same steps, undo and
// recovery: it ends with the release it left serving after its checks, or
// the one it returns to.

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
// there. It refuses with why otherwise.
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
		// Any rollback, done or undone: the upgrade it rolled back is no
		// longer the last change. Going back further is by hand.
		return RollbackPlan{}, fmt.Errorf("the last change was a rollback from %s to %s (%s): there is no upgrade to roll back. To restore the pre-upgrade snapshot by hand, stop varlatchd and run %s's varlatchd admin backup restore --in %s", last.From, last.To, last.State, last.To, last.Snapshot)
	case last.State == journal.Undone:
		return RollbackPlan{}, fmt.Errorf("the last upgrade, to %s, was undone and %s serves: there is nothing to roll back", last.To, last.From)
	}
	installed, err := binaryVersion(ctx, u.varlatchd())
	if err != nil {
		return RollbackPlan{}, err
	}
	if installed != last.To {
		return RollbackPlan{}, fmt.Errorf("varlatchd is %s, not %s, the release the last upgrade installed: a rollback returns only from that one", installed, last.To)
	}
	prev := filepath.Join(last.Releases, last.From)
	for _, name := range []string{"varlatch", "varlatchd"} {
		if info, err := os.Stat(filepath.Join(prev, name)); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return RollbackPlan{}, fmt.Errorf("%s's %s is not kept in %s: there is no previous release to roll back to", last.From, name, prev)
		}
	}
	if v, err := binaryVersion(ctx, filepath.Join(prev, "varlatchd")); err != nil || v != last.From {
		return RollbackPlan{}, fmt.Errorf("the varlatchd kept in %s is not %s: there is no previous release to roll back to", prev, last.From)
	}
	out, err := u.admin(ctx, filepath.Join(prev, "varlatchd"), "admin", "schema", "status", "--json")
	if err != nil {
		return RollbackPlan{}, fmt.Errorf("%s's varlatchd admin schema status: %v", last.From, err)
	}
	var st struct {
		Opens bool `json:"opens"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return RollbackPlan{}, fmt.Errorf("%s's varlatchd admin schema status gave no answer", last.From)
	}
	plan := RollbackPlan{Last: last, Declared: last.DeclaredRollbackSafe, Opens: st.Opens}
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
	if plan.Safe {
		return plan, nil
	}
	if info, err := os.Stat(last.Snapshot); last.Snapshot == "" || err != nil || !info.Mode().IsRegular() {
		return RollbackPlan{}, fmt.Errorf("%s; but the pre-upgrade snapshot (%s) is gone: a rollback would have nothing to restore", plan.Rule, last.Snapshot)
	}
	since, err := time.Parse(time.RFC3339, last.SnapshotAt)
	if err != nil {
		// A journal written before snapshots were dated: from the
		// upgrade's start, which lists more, never less.
		if since, err = time.Parse(time.RFC3339, last.StartedAt); err != nil {
			return RollbackPlan{}, errors.New("the upgrade journal says neither when the snapshot was taken nor when the upgrade began")
		}
	} else {
		since = since.Add(-lostMargin)
	}
	out, err = u.admin(ctx, u.varlatchd(), "admin", "changes", "--since", since.UTC().Format(time.RFC3339), "--json")
	if err != nil {
		return RollbackPlan{}, fmt.Errorf("listing the changes since the snapshot: %v", err)
	}
	var lost Changes
	if err := json.Unmarshal(out, &lost); err != nil {
		return RollbackPlan{}, errors.New("varlatchd admin changes gave no list")
	}
	plan.Lost = &lost
	return plan, nil
}

// binaryVersion is the release a varlatchd says it is.
func binaryVersion(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %v", path, err)
	}
	v, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "varlatchd ")
	if !ok {
		return "", fmt.Errorf("%s is not a release's varlatchd", path)
	}
	return v, nil
}

// Rollback runs plan: back to its upgrade's previous release. Its error is
// an *Error unless a crash point stopped it.
func (u *Upgrader) Rollback(ctx context.Context, plan RollbackPlan) (*journal.Journal, error) {
	unlock, err := lock(u.configDir())
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	defer unlock()
	last := plan.Last
	if now, err := journal.Read(u.configDir()); err != nil || now == nil || now.ID != last.ID || now.State != journal.Done || now.Kind != journal.Upgrade {
		return nil, &Error{Message: "the upgrade journal changed since the rollback was planned; nothing was changed"}
	}
	if err := upgradesDir(last.DataDir); err != nil {
		return nil, &Error{Message: err.Error() + "; nothing was changed"}
	}
	if !plan.Safe {
		if err := u.rollbackSpace(last.DataDir, last.SnapshotBytes); err != nil {
			return nil, &Error{Message: err.Error() + "; nothing was changed"}
		}
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, &Error{Message: err.Error()}
	}
	j := &journal.Journal{
		ID: hex.EncodeToString(id), Kind: journal.Rollback,
		From: last.To, To: last.From, FromSchema: last.ToSchema, ToSchema: last.FromSchema,
		RollbackSafe: plan.Safe, RollbackRule: plan.Rule, State: journal.InProgress, StartedAt: u.now().UTC().Format(time.RFC3339),
		BinDir: u.BinDir, Releases: last.Releases, DataDir: last.DataDir,
		Snapshot: last.Snapshot, SnapshotAt: last.SnapshotAt, SnapshotBytes: last.SnapshotBytes,
	}
	j.Work = filepath.Join(j.DataDir, "upgrades", j.ID)
	if err := u.write(j); err != nil {
		return nil, &Error{Message: fmt.Sprintf("cannot write the upgrade journal in %s: %v; nothing was changed", u.configDir(), err)}
	}
	err = u.rollbackSteps(ctx, j)
	if errors.Is(err, errKilled) {
		return j, err
	}
	if err != nil {
		reason := err.Error()
		if uerr := u.undo(ctx, j, reason); uerr != nil {
			if errors.Is(uerr, errKilled) {
				return j, uerr
			}
			return j, &Error{Message: uerr.Error(), Journal: j}
		}
		return j, &Error{Message: fmt.Sprintf("the rollback to %s did not complete (%s); it was undone: %s serves, on its database as it was", j.To, reason, j.From), Journal: j}
	}
	return j, nil
}

func (u *Upgrader) rollbackSteps(ctx context.Context, j *journal.Journal) error {
	if err := u.reach(j, journal.Verified); err != nil {
		return err
	}
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
		if err := u.restoreSnapshot(ctx, j); err != nil {
			return fmt.Errorf("restoring the pre-upgrade snapshot: %w", err)
		}
		u.logf("Restored the pre-upgrade snapshot with %s; the database it replaced is kept in %s.", j.To, filepath.Join(j.Work, "original"))
	}
	if err := u.reach(j, journal.Prepared); err != nil {
		return err
	}

	if err := u.install(j, j.To); err != nil {
		return fmt.Errorf("putting %s's binaries back: %w", j.To, err)
	}
	if err := u.reach(j, journal.Swapped); err != nil {
		return err
	}
	if err := u.Service.Start(ctx); err != nil {
		return fmt.Errorf("starting varlatchd %s: %w", j.To, err)
	}
	if err := u.reach(j, journal.Started); err != nil {
		return err
	}
	if err := u.check(ctx, j.To, j.ToSchema); err != nil {
		return fmt.Errorf("the health checks of %s: %w", j.To, err)
	}
	if err := u.reach(j, journal.Checked); err != nil {
		return err
	}
	return u.promote(j)
}

// restoreSnapshot keeps a copy of the database the rollback replaces (the
// undo puts it back; after a rollback it holds the changes it lost), then
// restores the pre-upgrade snapshot into the data directory with the
// previous release's varlatchd, varlatchd stopped.
func (u *Upgrader) restoreSnapshot(ctx context.Context, j *journal.Journal) error {
	original := filepath.Join(j.Work, "original")
	if err := u.workDir(j, original); err != nil {
		return err
	}
	for _, name := range databaseFiles {
		src := filepath.Join(j.DataDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := u.copyFile(src, filepath.Join(original, name), 0o600); err != nil {
			return err
		}
	}
	if err := ownAll(original, j.DataDir); err != nil {
		return err
	}
	syncDir(original)
	if err := u.point("rollback:current-kept"); err != nil {
		return err
	}
	if _, err := u.admin(ctx, filepath.Join(j.Releases, j.To, "varlatchd"), "admin", "backup", "restore", "--in", j.Snapshot); err != nil {
		return err
	}
	return u.point("rollback:restored")
}

// rollbackSpace: the data directory's filesystem must hold a copy of the
// current database and the restored one (the database the snapshot
// captured, snapshotBytes; the current one's size when the journal does not
// say), with spaceMargin to spare.
func (u *Upgrader) rollbackSpace(dataDir string, snapshotBytes int64) error {
	var db int64
	for _, name := range databaseFiles {
		if info, err := os.Stat(filepath.Join(dataDir, name)); err == nil {
			db += info.Size()
		}
	}
	restored := snapshotBytes
	if restored <= 0 {
		restored = db
	}
	free, _, err := FreeSpace(dataDir)
	if err != nil {
		return nil
	}
	if want := db + restored + spaceMargin; int64(free) < want {
		return fmt.Errorf("not enough space on the filesystem of %s: the rollback needs %d MiB free there (a copy of the database and the restored one, and %d MiB to spare), it has %d MiB",
			dataDir, want>>20, spaceMargin>>20, int64(free)>>20)
	}
	return nil
}
