// SPDX-License-Identifier: Apache-2.0

//go:build linux

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

var unsafeDecl = release.Declaration{SchemaVersion: toSchema, CompatibleFrom: toSchema, Previous: &release.Previous{Version: fromVersion, SchemaVersion: fromSchema}, ReversibleTo: &reversible}

// upgraded is a host upgraded from fromVersion to toVersion (rollback-safe, or not),
// with changes made after the upgrade: the installation bootstrapped by
// the new release.
func upgraded(t *testing.T, rollbackSafe bool) *host {
	t.Helper()
	if rollbackSafe {
		return upgradedWith(t, "to", safe)
	}
	return upgradedWith(t, "unsafe", unsafeDecl)
}

// upgradedWith is upgraded, with the new release's varlatchd build and
// the declaration its release.json makes.
func upgradedWith(t *testing.T, build string, d release.Declaration) *host {
	t.Helper()
	h := newHost(t)
	inst := h.inspect(t)
	rel := h.release(t, build, d)
	if j, err := h.upgrader(nil).Run(context.Background(), inst, rel); err != nil || j.State != journal.Done {
		t.Fatalf("the upgrade: %+v, %v", j, err)
	}
	if _, err := h.upgrader(nil).admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "bootstrap", "--cli-credential"); err != nil {
		t.Fatalf("a change after the upgrade: %v", err)
	}
	return h
}

// auditEvents is how many audit events the installed varlatchd counts
// since a time long ago.
func (h *host) auditEvents(t *testing.T) int64 {
	t.Helper()
	out, err := h.upgrader(nil).admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "changes", "--since", "2000-01-01T00:00:00Z", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var c Changes
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	return c.Total
}

func TestARollbackSafeRollbackKeepsEveryChange(t *testing.T) {
	h := upgraded(t, true)
	before := h.auditEvents(t)
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil || !plan.Safe || !plan.Declared || !plan.Opens || plan.Lost != nil || !strings.Contains(plan.Rule, "declares it rollback-safe for "+fromVersion+", and "+fromVersion+" opens the database") {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	j, err := h.upgrader(nil).Rollback(context.Background(), plan, nil)
	if err != nil || j.State != journal.Done || j.Kind != journal.Rollback || j.From != toVersion || j.To != fromVersion || !j.RollbackSafe || j.RollbackRule != plan.Rule {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
	if got := h.databaseSchema(); got != toSchema {
		t.Fatalf("the database kept its schema: %d", got)
	}
	if after := h.auditEvents(t); after < before {
		t.Fatalf("changes were lost: %d audit events before, %d after", before, after)
	}
	if _, err := os.Stat(filepath.Join(j.Work, "original")); !os.IsNotExist(err) {
		t.Fatalf("a rollback that keeps the database copied it: %v", err)
	}
	// The release returned to goes on with the newer database: it makes
	// archives that check and restore, and upgrades again, not to a release
	// below the database's schema.
	u := h.upgrader(nil)
	out, err := u.admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "backup", "run", "--json")
	var made struct {
		Path string `json:"path"`
	}
	if err != nil || json.Unmarshal(out, &made) != nil || made.Path == "" {
		t.Fatalf("a backup after the rollback: %v", err)
	}
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := u.admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "backup", "restore", "--in", made.Path); err != nil {
		t.Fatalf("its restore: %v", err)
	}
	// A restore may hold the installation; its operator resumes it.
	_ = os.Remove(filepath.Join(h.data, holdFile))
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.mustServe(t, fromVersion, fromSchema)
	// A second rollback has nothing to roll back.
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "the last change was a rollback") {
		t.Fatalf("a second rollback: %v", err)
	}
	inst, err := u.Inspect(context.Background())
	if err != nil || inst.Version != fromVersion || inst.Schema != fromSchema || inst.Database != toSchema {
		t.Fatalf("inspect after the rollback: %+v, %v", inst, err)
	}
	low := h.release(t, "to", safe)
	low.Manifest.SchemaVersion = fromSchema
	if _, err := u.Run(context.Background(), inst, low); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the database's schema is version %d", toSchema)) || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("an upgrade to a release below the database's schema: %v", err)
	}
	u.mustServe(t, fromVersion, fromSchema)
	if j, err := u.Run(context.Background(), inst, h.release(t, "to", safe)); err != nil || j.State != journal.Done {
		t.Fatalf("the upgrade again: %+v, %v", j, err)
	}
	u.mustServe(t, toVersion, toSchema)
	// And its rollback again, from a snapshot of the newer database.
	if plan, err = u.PlanRollback(context.Background()); err != nil || !plan.Safe {
		t.Fatalf("%+v, %v", plan, err)
	}
}

func TestARollbackFromTheSnapshotListsWhatIsLost(t *testing.T) {
	h := upgraded(t, false)
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil || plan.Safe || plan.Lost == nil || plan.Lost.Total == 0 || len(plan.Lost.Latest) == 0 || plan.Lost.Revocations == nil {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	// What is listed is what the restore loses: the bootstrap's events
	// among them, never a value.
	raw, _ := json.Marshal(plan.Lost)
	if !strings.Contains(string(raw), "installation.bootstrapped") && !strings.Contains(string(raw), "bootstrap") {
		t.Fatalf("the bootstrap is not listed: %s", raw)
	}
	if strings.Contains(string(raw), "vlt_") {
		t.Fatalf("a credential in the list: %s", raw)
	}
	j, err := h.upgrader(nil).Rollback(context.Background(), plan, nil)
	if err != nil || j.State != journal.Done || j.RollbackSafe {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
	if got := h.databaseSchema(); got != fromSchema {
		t.Fatalf("the snapshot's schema: %d", got)
	}
	// The listed changes are gone: since the same time, only what the
	// restore itself recorded (installation.restored) and the start remain.
	out, err := h.upgrader(nil).admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "changes", "--since", plan.Lost.Since, "--json")
	var now Changes
	if err != nil || json.Unmarshal(out, &now) != nil || now.Total >= plan.Lost.Total || now.ByType["installation.restored"] == 0 {
		t.Fatalf("after the restore, since %s: %+v (%v); listed before: %d", plan.Lost.Since, now, err, plan.Lost.Total)
	}
	kept := filepath.Join(j.Work, "original", "varlatch.db")
	if info, err := os.Stat(kept); err != nil || info.Size() == 0 {
		t.Fatalf("the replaced database is not kept: %v", err)
	}
	if exists(filepath.Join(h.data, backup.GateFile)) {
		t.Fatal("the restore left its gate open")
	}
}

func TestARollbackIsRefusedWithNothingToRollBackTo(t *testing.T) {
	// No upgrade recorded.
	h := newHost(t)
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "no upgrade is recorded") {
		t.Fatalf("no journal: %v", err)
	}

	// The previous release's binaries are gone.
	h = upgraded(t, true)
	u := h.upgrader(nil)
	if err := os.Remove(filepath.Join(u.Releases(), fromVersion, "varlatchd")); err != nil {
		t.Fatal(err)
	}
	if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "there is no previous release to roll back to: "+fromVersion+"'s varlatchd") {
		t.Fatalf("no previous binaries: %v", err)
	}

	// Not rollback-safe, and the snapshot is gone.
	h = upgraded(t, false)
	j, _ := journal.Read(filepath.Dir(h.conf))
	if err := os.Rename(j.Snapshot, j.Snapshot+".aside"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "the pre-upgrade snapshot") || !strings.Contains(err.Error(), "is gone") {
		t.Fatalf("no snapshot: %v", err)
	}
	// Another archive in its place, or the same one changed.
	if err := os.WriteFile(j.Snapshot, []byte("another archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "is not the one the upgrade recorded (SHA-256") {
		t.Fatalf("another archive: %v", err)
	}
	if err := os.Rename(j.Snapshot+".aside", j.Snapshot); err != nil {
		t.Fatal(err)
	}
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Changed between the plan and the stop: refused before the stop.
	if err := os.WriteFile(j.Snapshot+".new", []byte("another archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(j.Snapshot+".new", j.Snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).Rollback(context.Background(), plan, nil); err == nil || !strings.Contains(err.Error(), "is not the one the upgrade recorded") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("changed after the plan: %v", err)
	}
	h.upgrader(nil).mustServe(t, toVersion, toSchema)
}

// What would fail after the stop is refused before it: an archive that does
// not open with the host's key, a kept binary that is not the recorded one
// (it is not run), no database (a varlatchd started would make an empty
// one), an upgrade that recorded no checksums.
func TestARollbackIsRefusedBeforeTheStop(t *testing.T) {
	h := upgraded(t, false)
	u := h.upgrader(nil)
	backupKey := filepath.Join(h.dir, "keys", "backup-key")
	if err := os.Rename(backupKey, backupKey+".aside"); err != nil {
		t.Fatal(err)
	}
	key(t, backupKey)
	if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "the pre-upgrade snapshot does not restore") {
		t.Fatalf("another key: %v", err)
	}
	if err := os.Rename(backupKey+".aside", backupKey); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(h.data, ".restore-check")); !os.IsNotExist(err) {
		t.Fatalf("the check left its scratch: %v", err)
	}
	j, err := journal.Read(filepath.Dir(h.conf))
	if err != nil {
		t.Fatal(err)
	}
	kept, ran := filepath.Join(j.Releases, fromVersion, "varlatchd"), filepath.Join(h.dir, "ran")
	if err := os.Rename(kept, kept+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("#!/bin/sh\n: > "+ran+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "it is not run") {
		t.Fatalf("another binary: %v", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("it was run")
	}
	if err := os.Rename(kept+".aside", kept); err != nil {
		t.Fatal(err)
	}
	u.mustServe(t, toVersion, toSchema)

	noSums := *j
	noSums.Binaries = nil
	if err := journal.Write(filepath.Dir(h.conf), &noSums); err != nil {
		t.Fatal(err)
	}
	if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "did not record its binaries' checksums") || !strings.Contains(err.Error(), "backup restore --in "+j.Snapshot) {
		t.Fatalf("no checksums: %v", err)
	}
	if err := journal.Write(filepath.Dir(h.conf), j); err != nil {
		t.Fatal(err)
	}

	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{databaseFile, databaseFile + walSuffix, databaseFile + shmSuffix} {
		if err := os.Rename(filepath.Join(h.data, name), filepath.Join(h.dir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "there is no database in "+h.data) {
		t.Fatalf("no database: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(h.data, databaseFile)); !os.IsNotExist(err) {
		t.Fatalf("a database was made: %v", err)
	}
}

// Changes made between the list and the stop are listed again, after the
// stop: their loss is accepted, or the rollback is undone; and can be run
// again.
func TestARollbackAsksAgainForWhatWasMadeMeanwhile(t *testing.T) {
	h := upgraded(t, false)
	u := h.upgrader(nil)
	change := func() RollbackPlan {
		t.Helper()
		plan, err := u.PlanRollback(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.admin(context.Background(), filepath.Join(h.bin, "varlatchd"), "admin", "backup", "run", "--json"); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	plan := change()
	var asked *Changes
	j, err := u.Rollback(context.Background(), plan, func(now *Changes) (bool, error) { asked = now; return false, nil })
	if err == nil || !strings.Contains(err.Error(), ErrDeclined.Error()) || !strings.Contains(err.Error(), "It can be run again") || asked == nil || asked.Total <= plan.Lost.Total {
		t.Fatalf("%+v of %+v, %v", asked, plan.Lost, err)
	}
	upgradedServes(t, h, j)
	// Without anyone to ask, it is not accepted.
	if _, err = u.Rollback(context.Background(), change(), nil); err == nil || !strings.Contains(err.Error(), ErrDeclined.Error()) {
		t.Fatal(err)
	}
	plan, asked = change(), nil
	if j, err := u.Rollback(context.Background(), plan, func(now *Changes) (bool, error) { asked = now; return true, nil }); err != nil || j.State != journal.Done || asked == nil {
		t.Fatalf("%+v, %v", j, err)
	}
	u.mustServe(t, fromVersion, fromSchema)
}

// An upgrade that was undone has nothing to roll back.
func TestARollbackAfterAnUndoneUpgradeIsRefused(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	u := h.upgrader(nil)
	u.HealthTimeout = 3 * time.Second
	if _, err := u.Run(context.Background(), inst, h.release(t, "wrong", safe)); err == nil {
		t.Fatal("the upgrade succeeded")
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "was undone") {
		t.Fatalf("%v", err)
	}
}

// upgradedServes: the rollback was undone, and the upgraded release serves
// on the database it left.
func upgradedServes(t *testing.T, h *host, j *journal.Journal) {
	t.Helper()
	if j.State != journal.Undone {
		t.Fatalf("not undone: %+v", j)
	}
	h.upgrader(nil).mustServe(t, toVersion, toSchema)
	if got := h.databaseSchema(); got != toSchema {
		t.Fatalf("the database's schema after the undone rollback: %d", got)
	}
	if exists(filepath.Join(h.data, backup.GateFile)) {
		t.Fatal("a restore gate is left open")
	}
	for _, name := range append([]string{filepath.Join("upgrades", j.ID, originalDir)}, restoreLeftovers...) {
		if _, err := os.Lstat(filepath.Join(h.data, name)); !os.IsNotExist(err) {
			t.Fatalf("%s is left: %v", name, err)
		}
	}
	// The previous release's kept binaries survive the undo.
	for _, name := range binaryNames {
		if _, err := os.Stat(filepath.Join(h.upgrader(nil).Releases(), fromVersion, name)); err != nil {
			t.Fatalf("%s's %s is gone: %v", fromVersion, name, err)
		}
	}
	// The upgrade's record is back, with what became of its rollback, and it
	// can be rolled back.
	on, err := journal.Read(filepath.Dir(h.conf))
	if err != nil || on.Kind != journal.Upgrade || on.State != journal.Done || on.To != toVersion || on.LastRollback == nil || on.LastRollback.ID != j.ID || on.LastRollback.Reason == "" {
		t.Fatalf("the upgrade's record: %+v, %v", on, err)
	}
	if plan, err := h.upgrader(nil).PlanRollback(context.Background()); err != nil || plan.Last.ID != on.ID {
		t.Fatalf("after an undone rollback: %+v, %v", plan, err)
	}
}

// Killed at each point, the next run finishes the rollback (after its
// checks) or undoes it (before them): the release it returns to serves, or
// the one it left, on its database as it was.
func TestAKilledRollbackIsFinishedOrUndone(t *testing.T) {
	for _, c := range []struct {
		safe   bool
		points []string
	}{
		{false, []string{"stopping", "stop:done", "data:keep-original:rename:original", "install:" + fromVersion + ":varlatchd", "installed", "rollback:restored", "swapped", "started", "checked"}},
		{true, []string{"stop:done", "install:" + fromVersion + ":varlatchd", "started", "checked"}},
	} {
		for _, point := range c.points {
			name := point
			if c.safe {
				name = "safe:" + point
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				h := upgraded(t, c.safe)
				plan, err := h.upgrader(nil).PlanRollback(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				j, err := h.upgrader(func(p string) bool { return p == point }).Rollback(context.Background(), plan, nil)
				if !errors.Is(err, errKilled) || !j.Pending() {
					t.Fatalf("killed at %s: %+v, %v", point, j, err)
				}
				j, err = h.upgrader(nil).Recover(context.Background())
				if err != nil {
					t.Fatalf("recover: %v", err)
				}
				if point == "checked" {
					if j.State != journal.Done {
						t.Fatalf("after its checks, finished: %+v", j)
					}
					h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
					return
				}
				upgradedServes(t, h, j)
			})
		}
	}
}

// The database stays only on both counts: the release's declaration for
// the release returned to, and that release opening the database. Each
// other combination restores the snapshot and says which rule decided.
func TestTheRollbackRuleNeedsTheDeclarationAndTheOpenCheck(t *testing.T) {
	for _, c := range []struct {
		name            string
		build           string
		decl            release.Declaration
		declared, opens bool
		rule            string
	}{
		// Rollback-safe, but checked against another release (a skipped
		// one): the previous varlatchd opens the database, yet nothing
		// says it understands what is in it.
		{"not declared, opens", "to", release.Declaration{SchemaVersion: toSchema, CompatibleFrom: 1, RollbackSafe: true, Previous: &release.Previous{Version: "0.50.0-rc.0", SchemaVersion: fromSchema}, ReversibleTo: &reversible},
			false, true, "does not declare it rollback-safe for " + fromVersion + ": though " + fromVersion + " opens the database"},
		// Declared rollback-safe, but the database's compatible_from keeps
		// the previous varlatchd out (a declaration the build does not keep).
		{"declared, does not open", "unsafe", safe, true, false, "declares it rollback-safe for " + fromVersion + ", but " + fromVersion + " cannot open the database"},
		{"neither", "unsafe", unsafeDecl, false, false, "does not declare it rollback-safe for " + fromVersion + ", and " + fromVersion + " cannot open the database"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := upgradedWith(t, c.build, c.decl)
			plan, err := h.upgrader(nil).PlanRollback(context.Background())
			if err != nil || plan.Safe || plan.Declared != c.declared || plan.Opens != c.opens || plan.Lost == nil || !strings.Contains(plan.Rule, c.rule) {
				t.Fatalf("plan: %+v, %v", plan, err)
			}
			j, err := h.upgrader(nil).Rollback(context.Background(), plan, nil)
			if err != nil || j.State != journal.Done || j.RollbackSafe || j.RollbackRule != plan.Rule {
				t.Fatalf("%+v, %v", j, err)
			}
			h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
			// The snapshot's database, even where the previous varlatchd
			// would have opened the upgraded one.
			if got := h.databaseSchema(); got != fromSchema {
				t.Fatalf("the snapshot was not restored: schema %d", got)
			}
		})
	}
}

// An upgrade not over, or a release installed that is not the upgrade's:
// refused, nothing changed.
func TestARollbackIsRefusedOnAHostItDoesNotFit(t *testing.T) {
	h := upgraded(t, true)
	dir := filepath.Dir(h.conf)
	done, err := journal.Read(dir)
	if err != nil || done.SnapshotBytes <= 0 {
		t.Fatalf("the upgrade records the snapshot's database size: %+v, %v", done, err)
	}
	pending := *done
	pending.State, pending.Step = journal.InProgress, journal.Stopped
	if err := journal.Write(dir, &pending); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "an upgrade from ") || !strings.Contains(err.Error(), "is not over") || !strings.Contains(err.Error(), "run varlatch upgrade first") {
		t.Fatalf("an upgrade not over: %v", err)
	}
	// An interrupted rollback is named as one.
	pending.Kind, pending.Upgraded = journal.Rollback, done
	if err := journal.Write(dir, &pending); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "a rollback from ") || !strings.Contains(err.Error(), "is not over") {
		t.Fatalf("a rollback not over: %v", err)
	}
	if err := journal.Write(dir, done); err != nil {
		t.Fatal(err)
	}
	// Another varlatchd in place than the one the upgrade installed.
	if err := os.WriteFile(filepath.Join(h.bin, "varlatchd.other"), build(t, "from"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(h.bin, "varlatchd.other"), filepath.Join(h.bin, "varlatchd")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "is not the varlatchd the upgrade to "+toVersion+" installed") {
		t.Fatalf("another release installed: %v", err)
	}
}

// A release before RollbackSince cannot read the journal a rollback to it
// leaves: refused, with the way back by hand.
func TestARollbackNeedsAReleaseThatReadsIt(t *testing.T) {
	for v, want := range map[string]bool{"0.50.0-rc.3": false, "0.50.0-rc.4": true, "0.50.0-rc.10": true, "0.50.0": true, "0.51.0-rc.1": true, "0.23.0": false, "x": false} {
		if ReturnsTo(v) != want {
			t.Errorf("%s: %v", v, !want)
		}
	}
	dir := t.TempDir()
	u := &Upgrader{BinDir: filepath.Join(dir, "bin"), ConfigPath: filepath.Join(dir, "varlatchd.conf")}
	uid, gid := os.Getuid(), os.Getgid()
	for _, c := range []struct {
		from   string
		format int
		want   string
	}{
		{"0.50.0-rc.2", journal.FormatOne, "0.50.0-rc.2's varlatch cannot read a rollback's journal (0.50.0-rc.4 is the first that can), so it could neither finish an interrupted rollback nor upgrade after one. By hand, losing every change made since the upgrade:\n" +
			"  sudo systemctl stop varlatchd\n" +
			"  sudo install -m 755 /r/0.50.0-rc.2/varlatch /r/0.50.0-rc.2/varlatchd BIN\n" +
			"  sudo BIN/varlatchd admin backup restore --in '/s p.vltbak' --config CONF\n" +
			fmt.Sprintf("  sudo chown -R --no-dereference --from=0 %d:%d DIR\n", uid, gid) +
			"  sudo systemctl start varlatchd"},
		{"0.50.0-rc.3", journal.Format, "  sudo mv DIR/upgrade.json DIR/upgrade-x.json\n  sudo systemctl start varlatchd"},
	} {
		if err := journal.Write(dir, &journal.Journal{Format: c.format, ID: "x", From: c.from, To: "0.50.0-rc.4", State: journal.Done, Step: journal.Checked,
			StartedAt: "2026-11-24T00:00:00Z", Releases: "/r", DataDir: dir, Snapshot: "/s p.vltbak"}); err != nil {
			t.Fatal(err)
		}
		want := strings.NewReplacer("BIN", u.BinDir, "CONF", u.ConfigPath, "DIR", dir).Replace(c.want)
		if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%v\nwant\n%s", err, want)
		}
	}
}

// migration writes a migration's journal into the data directory, at
// phase, switched at at.
func (h *host) migration(t *testing.T, phase migrate.Phase, at time.Time, change func(*migrate.Journal)) {
	t.Helper()
	j := &migrate.Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: phase, Ingress: migrate.Proxy,
		History: []migrate.Step{{Phase: migrate.Switched, At: at.UTC().Format(time.RFC3339Nano)}}}
	if change != nil {
		change(j)
	}
	b, err := j.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.data, migrate.JournalFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Beside a migration's rollback window the rollback says what becomes of
// it; one under way, or one the upgrade came before, or a gate, is refused
// and nothing changes, also when it came after the plan.
func TestARollbackBesideAMigration(t *testing.T) {
	h := upgraded(t, true)
	u := h.upgrader(nil)
	before, after := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for _, c := range []struct {
		name   string
		phase  migrate.Phase
		at     time.Time
		change func(*migrate.Journal)
		gate   string
		note   string
		want   string
	}{
		{name: "the window open", phase: migrate.Open, at: before, note: "its rollback window stays open until "},
		{name: "ended by the upgrade", phase: migrate.Open, at: before, change: func(j *migrate.Journal) {
			j.WindowEnded = &migrate.WindowEndedRecord{Release: toVersion, At: before.UTC().Format(time.RFC3339Nano)}
		}, note: "its rollback window was ended by the upgrade to " + toVersion + ", and stays ended"},
		{name: "past the window", phase: migrate.Open, at: time.Now().Add(-31 * 24 * time.Hour)},
		{name: "finished", phase: migrate.Finished, at: before},
		{name: "migrated after the upgrade", phase: migrate.Open, at: after, want: "are from before the migration"},
		{name: "finished after the upgrade", phase: migrate.Finished, at: after, want: "are from before the migration"},
		{name: "a reverse under way", phase: migrate.Rollback, at: before, want: "in phase rollback: finish or abort it first"},
		{name: "a transfer", phase: migrate.Transfer, at: before, want: "in phase transfer: finish or abort it first"},
		{name: "rolled back", phase: migrate.RolledBack, at: before, want: "in phase rolled-back: finish or abort it first"},
		{name: "no switch recorded", phase: migrate.Open, at: before, change: func(j *migrate.Journal) { j.History = nil }, want: "does not say when the migration switched"},
		{name: "a barrier", phase: migrate.Open, at: before, gate: `{"id":"mig_aaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"migration","phase":"draining"}`, want: "a migration's gate stands"},
		{name: "a restore", phase: migrate.Open, at: before, gate: `{"id":"x","kind":"restore","phase":"paused","archiveId":"a"}`, want: "kind restore): end it first"},
		{name: "a capture", phase: migrate.Open, at: before, gate: `{"id":"x","kind":"capture","phase":"draining","expiresAt":` + strconv.FormatInt(after.UnixMilli(), 10) + `}`, want: "kind capture): end it first"},
		{name: "a capture's lease expired", phase: migrate.Open, at: before, gate: `{"id":"x","kind":"capture","phase":"draining","expiresAt":` + strconv.FormatInt(before.UnixMilli(), 10) + `}`, note: "stays open until"},
		{name: "a gate that cannot be read", phase: migrate.Open, at: before, gate: `{`, want: "the maintenance gate"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.migration(t, c.phase, c.at, c.change)
			gate := filepath.Join(h.data, backup.GateFile)
			if c.gate != "" {
				if err := os.WriteFile(gate, []byte(c.gate), 0o600); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(gate)
			}
			plan, err := u.PlanRollback(context.Background())
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("%v, want %q", err, c.want)
				}
				return
			}
			if err != nil || c.note == "" && plan.Migration != "" || !strings.Contains(plan.Migration, c.note) {
				t.Fatalf("%+v, %v", plan, err)
			}
		})
	}
	// Begun after the plan: refused, nothing changed.
	h.migration(t, migrate.Open, before, nil)
	plan, err := u.PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.migration(t, migrate.Rollback, before, nil)
	if _, err := u.Rollback(context.Background(), plan, nil); err == nil || !strings.Contains(err.Error(), "in phase rollback") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("%v", err)
	}
	u.mustServe(t, toVersion, toSchema)
	h.migration(t, migrate.Open, before, nil)
	if j, err := u.Rollback(context.Background(), plan, nil); err != nil || j.State != journal.Done {
		t.Fatalf("%+v, %v", j, err)
	}
	u.mustServe(t, fromVersion, fromSchema)
}

// Another data directory in the configuration than the upgrade's: refused.
func TestARollbackIsRefusedInAnotherDataDirectory(t *testing.T) {
	h := upgraded(t, true)
	dir := filepath.Dir(h.conf)
	j, err := journal.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	j.DataDir = filepath.Join(h.dir, "another")
	if err := os.Mkdir(j.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := journal.Write(dir, j); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "names the data directory "+h.data+", and the upgrade was made in "+j.DataDir) {
		t.Fatalf("%v", err)
	}
}

// While a varlatchd command of the interrupted run still holds the data
// directory, an undo changes nothing in it; run again after, it undoes.
func TestAnUndoWaitsForTheDataDirectory(t *testing.T) {
	h := upgraded(t, false)
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(func(p string) bool { return p == "rollback:restored" }).Rollback(context.Background(), plan, nil); !errors.Is(err, errKilled) {
		t.Fatal(err)
	}
	unlock, err := lockData(filepath.Join(h.data, lockFile))
	if err != nil {
		t.Fatal(err)
	}
	j, err := h.upgrader(nil).Recover(context.Background())
	unlock()
	if err == nil || !strings.Contains(err.Error(), "the rollback to "+fromVersion+" failed") || !strings.Contains(err.Error(), "still uses "+h.data) || j.State != journal.Failed {
		t.Fatalf("%+v, %v", j, err)
	}
	if got := h.databaseSchema(); got != fromSchema {
		t.Fatalf("the database was put back under a lock: schema %d", got)
	}
	if j, err = h.upgrader(nil).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	upgradedServes(t, h, j)
}

// A run whose time is over is undone all the same.
func TestAnUndoOutlivesTheRunsTime(t *testing.T) {
	h := upgraded(t, false)
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j, err := h.upgrader(func(p string) bool {
		if p == "stopped" {
			cancel()
		}
		return false
	}).Rollback(ctx, plan, nil)
	if err == nil || !strings.Contains(err.Error(), "it was undone") {
		t.Fatalf("%v", err)
	}
	upgradedServes(t, h, j)
}

// As root with varlatchd another user's, as the unit runs it: the database
// the rollback restores is that user's, and served.
func TestARollbackAsRootGivesTheServerItsDatabase(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runs varlatchd as another user, as root (go.yml's Go container)")
	}
	const uid = 65534
	h := newHostOf(t, uid)
	inst := h.inspect(t)
	if j, err := h.upgrader(nil).Run(context.Background(), inst, h.release(t, "unsafe", unsafeDecl)); err != nil || j.State != journal.Done {
		t.Fatalf("the upgrade: %+v, %v", j, err)
	}
	// Planned with varlatchd stopped too, as when the new release does not
	// start: the reads leave nothing of root's that varlatchd meets.
	if err := h.svc.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	j, err := h.upgrader(nil).Rollback(context.Background(), plan, nil)
	if err != nil || j.State != journal.Done {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
	for _, name := range []string{databaseFile, databaseFile + walSuffix, databaseFile + shmSuffix} {
		info, err := os.Stat(filepath.Join(h.data, name))
		if err == nil && info.Sys().(*syscall.Stat_t).Uid != uid {
			t.Errorf("%s is uid %d's", name, info.Sys().(*syscall.Stat_t).Uid)
		}
	}
}

// Killed in the middle of the restore: the database it was writing, its
// gate, the archive it opened and the one it had not put in place all go,
// and the release left serves on its own database.
func TestAKillInTheRestore(t *testing.T) {
	h := upgraded(t, false)
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(func(p string) bool { return p == "installed" }).Rollback(context.Background(), plan, nil); !errors.Is(err, errKilled) {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(h.data, ".restore-work"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The restore replaces the database by a rename, never in place.
	if err := os.Remove(filepath.Join(h.data, databaseFile)); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(h.data, databaseFile+walSuffix))
	for name, content := range map[string]string{
		"varlatch.db": "a part", "varlatch.db-wal": "another", "varlatch.db.restore": "a part", ".restore-work/database.sqlite": "an archive's",
		backup.GateFile: `{"id":"x","kind":"restore","phase":"paused","archiveId":"a"}`,
	} {
		if err := os.WriteFile(filepath.Join(h.data, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j, err := h.upgrader(nil).Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	upgradedServes(t, h, j)
}
