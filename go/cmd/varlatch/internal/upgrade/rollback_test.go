// SPDX-License-Identifier: Apache-2.0

//go:build linux

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

var unsafeDecl = release.Declaration{SchemaVersion: 2, CompatibleFrom: 2, Previous: &release.Previous{Version: fromVersion, SchemaVersion: 1}}

// upgraded is a host upgraded from rc.1 to rc.2 (rollback-safe, or not),
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
	j, err := h.upgrader(nil).Rollback(context.Background(), plan)
	if err != nil || j.State != journal.Done || j.Kind != journal.Rollback || j.From != toVersion || j.To != fromVersion || !j.RollbackSafe || j.RollbackRule != plan.Rule {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, 1)
	if got := h.databaseSchema(); got != 2 {
		t.Fatalf("the database kept its schema: %d", got)
	}
	if after := h.auditEvents(t); after < before {
		t.Fatalf("changes were lost: %d audit events before, %d after", before, after)
	}
	if _, err := os.Stat(filepath.Join(j.Work, "original")); !os.IsNotExist(err) {
		t.Fatalf("a rollback that keeps the database copied it: %v", err)
	}
	// A second rollback has nothing to roll back.
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "the last change was a rollback") {
		t.Fatalf("a second rollback: %v", err)
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
	j, err := h.upgrader(nil).Rollback(context.Background(), plan)
	if err != nil || j.State != journal.Done || j.RollbackSafe {
		t.Fatalf("%+v, %v", j, err)
	}
	h.upgrader(nil).mustServe(t, fromVersion, 1)
	if got := h.databaseSchema(); got != 1 {
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
	if restoreGateOpen(h.data) {
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
	if _, err := u.PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "is not kept") {
		t.Fatalf("no previous binaries: %v", err)
	}

	// Not rollback-safe, and the snapshot is gone.
	h = upgraded(t, false)
	j, _ := journal.Read(filepath.Dir(h.conf))
	if err := os.Remove(j.Snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "the pre-upgrade snapshot") || !strings.Contains(err.Error(), "is gone") {
		t.Fatalf("no snapshot: %v", err)
	}
	h.upgrader(nil).mustServe(t, toVersion, 2)
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
	h.upgrader(nil).mustServe(t, toVersion, 2)
	if got := h.databaseSchema(); got != 2 {
		t.Fatalf("the database's schema after the undone rollback: %d", got)
	}
	if restoreGateOpen(h.data) {
		t.Fatal("a restore gate is left open")
	}
	// The previous release's kept binaries survive the undo.
	for _, name := range []string{"varlatch", "varlatchd"} {
		if _, err := os.Stat(filepath.Join(h.upgrader(nil).Releases(), fromVersion, name)); err != nil {
			t.Fatalf("%s's %s is gone: %v", fromVersion, name, err)
		}
	}
	// A rollback is not run twice, done or undone: going back further is
	// by hand, and the refusal says how.
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "the last change was a rollback") ||
		!strings.Contains(err.Error(), "varlatchd admin backup restore --in "+j.Snapshot) {
		t.Fatalf("after an undone rollback: %v", err)
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
		{false, []string{"verified", "stopping", "stop:done", "stopped", "rollback:current-kept", "rollback:restored", "prepared",
			"install:" + fromVersion + ":varlatchd", "install:" + fromVersion + ":varlatch", "swapped", "started", "checked"}},
		{true, []string{"stop:done", "prepared", "install:" + fromVersion + ":varlatchd", "started", "checked"}},
	} {
		for _, point := range c.points {
			name := point
			if c.safe {
				name = "safe:" + point
			}
			t.Run(name, func(t *testing.T) {
				h := upgraded(t, c.safe)
				plan, err := h.upgrader(nil).PlanRollback(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				j, err := h.upgrader(func(p string) bool { return p == point }).Rollback(context.Background(), plan)
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
					h.upgrader(nil).mustServe(t, fromVersion, 1)
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
		{"not declared, opens", "to", release.Declaration{SchemaVersion: 2, CompatibleFrom: 1, RollbackSafe: true, Previous: &release.Previous{Version: "0.50.0-rc.0", SchemaVersion: 1}},
			false, true, "does not declare it rollback-safe for " + fromVersion + ": though " + fromVersion + " opens the database"},
		// Declared rollback-safe, but the database's compatible_from keeps
		// the previous varlatchd out (a declaration the build does not keep).
		{"declared, does not open", "unsafe", safe, true, false, "declares it rollback-safe for " + fromVersion + ", but " + fromVersion + " cannot open the database"},
		{"neither", "unsafe", unsafeDecl, false, false, "does not declare it rollback-safe for " + fromVersion + ", and " + fromVersion + " cannot open the database"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := upgradedWith(t, c.build, c.decl)
			plan, err := h.upgrader(nil).PlanRollback(context.Background())
			if err != nil || plan.Safe || plan.Declared != c.declared || plan.Opens != c.opens || plan.Lost == nil || !strings.Contains(plan.Rule, c.rule) {
				t.Fatalf("plan: %+v, %v", plan, err)
			}
			j, err := h.upgrader(nil).Rollback(context.Background(), plan)
			if err != nil || j.State != journal.Done || j.RollbackSafe || j.RollbackRule != plan.Rule {
				t.Fatalf("%+v, %v", j, err)
			}
			h.upgrader(nil).mustServe(t, fromVersion, 1)
			// The snapshot's database, even where the previous varlatchd
			// would have opened the upgraded one.
			if got := h.databaseSchema(); got != 1 {
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
	pending.Kind = journal.Rollback
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
	if _, err := h.upgrader(nil).PlanRollback(context.Background()); err == nil || !strings.Contains(err.Error(), "varlatchd is "+fromVersion+", not "+toVersion) {
		t.Fatalf("another release installed: %v", err)
	}
}
