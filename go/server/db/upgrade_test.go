// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/db/query"
)

// Two synthetic releases after the current schema: version +1 adds (rollback
// safe), version +2 removes (not rollback-safe).
func syntheticSteps() ([]Step, int64) {
	steps := append([]Step(nil), steps...)
	n := int64(SchemaVersion)
	steps = append(steps,
		Step{To: n + 1, CompatibleFrom: CompatibleFrom, SQL: "CREATE TABLE upgrade_added (id INTEGER NOT NULL PRIMARY KEY, note TEXT) STRICT; INSERT INTO upgrade_added (note) VALUES ('a');"},
		Step{To: n + 2, CompatibleFrom: n + 2, SQL: "ALTER TABLE upgrade_added DROP COLUMN note;"},
	)
	return steps, n + 2
}

func versionOf(t *testing.T, ctx context.Context, q *query.Queries) query.GetSchemaVersionRow {
	t.Helper()
	v, err := q.GetSchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestUpgradeAppliesEveryStepInOneJob(t *testing.T) {
	ctx := context.Background()
	s := openDB(t)
	before := versionOf(t, ctx, query.New(s.Reader()))
	steps, target := syntheticSteps()

	// One step: the rollback-safe one keeps the previous version's
	// compatible_from.
	up, err := upgrade(ctx, s, "0.50.1", steps[:target-2], target-1, CompatibleFrom)
	if err != nil || !up.Changed || up.From != SchemaVersion || up.To != target-1 || up.CompatibleFrom != CompatibleFrom {
		t.Fatalf("upgrade by one rollback-safe step: %+v, %v", up, err)
	}
	v := versionOf(t, ctx, query.New(s.Reader()))
	if v.Version != target-1 || v.CompatibleFrom != CompatibleFrom || v.UpdatedByRelease != "0.50.1" ||
		v.CreatedByRelease != before.CreatedByRelease || v.CreatedAt != before.CreatedAt || v.UpdatedAt <= before.UpdatedAt {
		t.Fatalf("schema_version after the upgrade: %+v (before %+v)", v, before)
	}
	var note string
	if err := s.Reader().QueryRowContext(ctx, "SELECT note FROM upgrade_added").Scan(&note); err != nil || note != "a" {
		t.Fatalf("the step's row: %q, %v", note, err)
	}

	// This varlatchd still opens it: the step was rollback-safe.
	if st, err := Init(ctx, s, testRelease); err != nil || st.Version != target-1 {
		t.Fatalf("Init after a rollback-safe upgrade: %+v, %v", st, err)
	}

	// Again with the same steps: nothing to do.
	up, err = upgrade(ctx, s, "0.50.1", steps[:target-2], target-1, CompatibleFrom)
	if err != nil || up.Changed || up.From != target-1 || up.To != target-1 {
		t.Fatalf("a second upgrade to the same version: %+v, %v", up, err)
	}

	// The next step is not rollback-safe: compatible_from moves to it, and
	// this varlatchd no longer opens the database.
	up, err = upgrade(ctx, s, "0.51.0", steps, target, target)
	if err != nil || !up.Changed || up.From != target-1 || up.To != target || up.CompatibleFrom != target {
		t.Fatalf("upgrade by a step that is not rollback-safe: %+v, %v", up, err)
	}
	var ve *VersionError
	if _, err := Init(ctx, s, testRelease); !errors.As(err, &ve) || ve.Database != target || ve.CompatibleFrom != target {
		t.Fatalf("Init after an upgrade that is not rollback-safe: %v", err)
	}
	// Nor does an older Upgrade change it.
	if _, err := Upgrade(ctx, s, testRelease); !errors.As(err, &ve) {
		t.Fatalf("Upgrade of a newer database it may not open: %v", err)
	}
}

func TestUpgradeFromTheFirstVersionRunsEveryStep(t *testing.T) {
	ctx := context.Background()
	s := openDB(t)
	steps, target := syntheticSteps()
	up, err := upgrade(ctx, s, testRelease, steps, target, target)
	if err != nil || up.From != SchemaVersion || up.To != target {
		t.Fatalf("%+v, %v", up, err)
	}
	var cols int
	if err := s.Reader().QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('upgrade_added')").Scan(&cols); err != nil || cols != 1 {
		t.Fatalf("both steps ran: %d columns, %v", cols, err)
	}
}

// A step that fails leaves the database as it was: no step before it, no
// version recorded.
func TestAFailedUpgradeChangesNothing(t *testing.T) {
	ctx := context.Background()
	s := openDB(t)
	steps, target := syntheticSteps()
	steps[len(steps)-1].SQL = "ALTER TABLE no_such_table ADD COLUMN x TEXT;"
	_, err := upgrade(ctx, s, testRelease, steps, target, target)
	if err == nil || !strings.Contains(err.Error(), "upgrading the schema to version") {
		t.Fatalf("a failing step: %v", err)
	}
	if v := versionOf(t, ctx, query.New(s.Reader())); v.Version != SchemaVersion {
		t.Fatalf("version after a failed upgrade: %+v", v)
	}
	var n int
	if err := s.Reader().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name = 'upgrade_added'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("the first step's table survived the failed upgrade: %d, %v", n, err)
	}
}

func TestUpgradeRefusesWhatIsNotAVarlatchDatabase(t *testing.T) {
	ctx := context.Background()
	empty := openFile(t, filepath.Join(t.TempDir(), "varlatch.db"))
	defer empty.Close()
	if _, err := Upgrade(ctx, empty, testRelease); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("an empty database: %v", err)
	}
	var n int
	if err := empty.Reader().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&n); err != nil || n != 0 {
		t.Fatalf("Upgrade created something in an empty database: %d, %v", n, err)
	}

	other := openFile(t, filepath.Join(t.TempDir(), "other.db"))
	defer other.Close()
	exec(t, other, "CREATE TABLE notes (id INTEGER PRIMARY KEY)")
	if _, err := Upgrade(ctx, other, testRelease); !errors.Is(err, ErrNotVarlatch) {
		t.Fatalf("a database without schema_version: %v", err)
	}

	s := openDB(t)
	for _, r := range []string{"", strings.Repeat("9", 65)} {
		if _, err := Upgrade(ctx, s, r); err == nil {
			t.Fatalf("Upgrade with release %q succeeded", r)
		}
	}
}

// The steps this varlatchd carries are well formed, and a database it
// creates needs none of them.
func TestTheStepsReachSchemaVersion(t *testing.T) {
	if err := checkSteps(steps, SchemaVersion, CompatibleFrom); err != nil {
		t.Fatal(err)
	}
	up, err := Upgrade(context.Background(), openDB(t), testRelease)
	if err != nil || up.Changed || up.To != SchemaVersion || up.CompatibleFrom != CompatibleFrom {
		t.Fatalf("Upgrade of a new database: %+v, %v", up, err)
	}
}

func TestCheckStepsRefusesMalformedSteps(t *testing.T) {
	for _, c := range []struct {
		name           string
		steps          []Step
		target, compat int64
		want           string
	}{
		{"a missing step", []Step{{To: 2, CompatibleFrom: 1}}, 3, 1, "1 upgrade steps for schema version 3"},
		{"out of order", []Step{{To: 3, CompatibleFrom: 1}, {To: 2, CompatibleFrom: 1}}, 3, 1, "goes to version 3; want 2"},
		{"compatibility going down", []Step{{To: 2, CompatibleFrom: 2}, {To: 3, CompatibleFrom: 1}}, 3, 1, "compatibleFrom 1 is not between 2 and 3"},
		{"compatibility above its version", []Step{{To: 2, CompatibleFrom: 3}}, 2, 3, "compatibleFrom 3 is not between 1 and 2"},
		{"CompatibleFrom not the last step's", []Step{{To: 2, CompatibleFrom: 1}}, 2, 2, "CompatibleFrom is 2; the last upgrade step's is 1"},
	} {
		if err := checkSteps(c.steps, c.target, c.compat); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
