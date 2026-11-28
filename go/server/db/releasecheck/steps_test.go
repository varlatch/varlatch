// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/db"
)

// withSteps makes the release check see this build's steps and then extra,
// as a build with more steps would, until the test ends.
func withSteps(t *testing.T, extra ...db.Step) {
	t.Helper()
	saved := upgradeSteps
	t.Cleanup(func() { upgradeSteps = saved })
	upgradeSteps = func() []db.Step { return append(db.Steps(), extra...) }
}

func writeFile(t *testing.T, name, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g6, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// stepDecl is a declaration of schema version to, compatible from cf,
// against a previous release of this build's schema.
func stepDecl(t *testing.T, to, cf int64) string {
	t.Helper()
	return writeFile(t, "release.json", fmt.Sprintf(`{"schemaVersion": %d, "compatibleFrom": %d, "rollbackSafe": %t, "previous": {"version": "0.0.0-g6.base", "schemaVersion": %d}, "reversibleTo": "0.23.1", "endsRollbackWindow": false}`,
		to, cf, cf <= db.SchemaVersion, db.SchemaVersion))
}

// A step that declares itself rollback-safe while its own change is not
// fails the check, naming the step and the change, even where the
// declaration as a whole holds: varlatchd serve applies such a step at
// start in the image, and the varlatchd before it could not go back to the
// result.
func TestAMisdeclaredStepFails(t *testing.T) {
	sv := int64(db.SchemaVersion)
	previous := writeFile(t, "previous.sql", db.Schema())
	newTable := "CREATE TABLE g6_steps (id INTEGER NOT NULL PRIMARY KEY, note TEXT) STRICT;\n"
	onNewTable := "CREATE TRIGGER g6_steps_closed BEFORE INSERT ON g6_steps BEGIN SELECT RAISE(ABORT, 'closed'); END;\n"
	for _, c := range []struct {
		name    string
		steps   []db.Step
		current string
		cf      int64 // the declaration's compatibleFrom
		problem string
	}{
		{
			// G6's breaking fixture as a step declared rollback-safe, then a
			// step that is not: the declaration (not rollback-safe) holds,
			// the first step's own declaration does not.
			name: "a breaking step before one that is not rollback-safe",
			steps: []db.Step{
				{To: sv + 1, CompatibleFrom: 1, SQL: fixture(t, "breaking.sql")},
				{To: sv + 2, CompatibleFrom: sv + 2, SQL: fixture(t, "additive.sql")},
			},
			current: db.Schema() + fixture(t, "breaking.sql") + fixture(t, "additive.sql"),
			cf:      sv + 2,
			problem: fmt.Sprintf("PROBLEM: the step to schema %d declares compatibleFrom 1, so the varlatchd of schema %d must still open the database after it, but breaking: trigger g6_breaking_no_new_identities: a new trigger on the existing table identities", sv+1, sv),
		},
		{
			// Against the previous release, the trigger is on a new table
			// (additive); against the step before it, on an existing one.
			name: "a trigger on the table the step before added",
			steps: []db.Step{
				{To: sv + 1, CompatibleFrom: 1, SQL: newTable},
				{To: sv + 2, CompatibleFrom: 1, SQL: onNewTable},
			},
			current: db.Schema() + newTable + onNewTable,
			cf:      1,
			problem: fmt.Sprintf("PROBLEM: the step to schema %d declares compatibleFrom 1, so the varlatchd of schema %d must still open the database after it, but breaking: trigger g6_steps_closed: a new trigger on the existing table g6_steps", sv+2, sv+1),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			withSteps(t, c.steps...)
			decl := stepDecl(t, sv+2, c.cf)
			current := writeFile(t, "current.sql", c.current)
			code, out, errs := runIt(t, "schema", "--previous", previous, "--current", current, "--declaration", decl)
			if code != exitFailed || !strings.Contains(out, c.problem) || strings.Count(out, "PROBLEM") != 1 || !strings.Contains(errs, "1 problems: the declaration does not hold") {
				t.Fatalf("%d %q %q", code, out, errs)
			}
			// Declared not rollback-safe, the same step passes.
			fixed := append([]db.Step(nil), c.steps...)
			for i := range fixed {
				fixed[i].CompatibleFrom = sv + 2
			}
			withSteps(t, fixed...)
			code, out, errs = runIt(t, "schema", "--previous", previous, "--current", current, "--declaration", stepDecl(t, sv+2, sv+2))
			if code != exitOK || strings.Contains(out, "PROBLEM") || !strings.Contains(out, fmt.Sprintf("note: the step to schema %d (compatible from %d): 1 schema changes, not rollback-safe", sv+1, sv+2)) {
				t.Fatalf("declared not rollback-safe: %d %q %q", code, out, errs)
			}
		})
	}
}

// The schema the steps give must be the one the declaration was held
// against: otherwise what an upgrade runs is not what was judged.
func TestStepsThatDoNotGiveTheSchemaFail(t *testing.T) {
	sv := int64(db.SchemaVersion)
	withSteps(t, db.Step{To: sv + 1, CompatibleFrom: 1, SQL: "CREATE TABLE g6_steps (id INTEGER NOT NULL PRIMARY KEY) STRICT;"})
	previous := writeFile(t, "previous.sql", db.Schema())
	current := writeFile(t, "current.sql", db.Schema()+fixture(t, "additive.sql"))
	code, out, errs := runIt(t, "schema", "--previous", previous, "--current", current, "--declaration", stepDecl(t, sv+1, 1))
	want := fmt.Sprintf("PROBLEM: the upgrade steps from schema %d do not give the schema checked here", sv)
	if code != exitFailed || !strings.Contains(out, want) || !strings.Contains(out, "table g6_steps: removed") || !strings.Contains(out, "table g6_fixture: added") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

// The real schema history: every step of this build, from 0.50.0-rc.1's
// schema (version 1) on, holds its own declaration and gives this build's
// schema.
func TestTheRealStepsHoldTheirDeclarations(t *testing.T) {
	decl := writeFile(t, "release.json", fmt.Sprintf(`{"schemaVersion": %d, "compatibleFrom": %d, "rollbackSafe": %t, "previous": {"version": "0.50.0-rc.1", "schemaVersion": 1}, "reversibleTo": "0.23.1", "endsRollbackWindow": false}`,
		db.SchemaVersion, db.CompatibleFrom, db.CompatibleFrom <= 1))
	code, out, errs := runIt(t, "schema", "--previous", filepath.Join("testdata", "schema-0.50.0-rc.1.sql"), "--declaration", decl, "--json")
	var doc struct {
		Steps []struct {
			To             int64             `json:"to"`
			CompatibleFrom int64             `json:"compatibleFrom"`
			Changes        []json.RawMessage `json:"changes"`
		} `json:"steps"`
		Problems []string `json:"problems"`
		Notes    []string `json:"notes"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &doc) != nil || len(doc.Problems) != 0 || int64(len(doc.Steps)) != db.SchemaVersion-1 {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	for i, st := range doc.Steps {
		real := db.Steps()[i]
		if st.To != real.To || st.CompatibleFrom != real.CompatibleFrom || len(st.Changes) == 0 {
			t.Errorf("step %d: %+v", i, st)
		}
		note := fmt.Sprintf("the step to schema %d (compatible from %d): %d schema changes", st.To, st.CompatibleFrom, len(st.Changes))
		if !strings.Contains(out, note) {
			t.Errorf("no note %q", note)
		}
	}
}

// Steps that do not reach the declaration's schema version are another
// build's: a note says they are not judged.
func TestStepsOfAnotherVersionAreNotJudged(t *testing.T) {
	if db.SchemaVersion == 8 {
		t.Skip("this build's steps reach the fixture's version")
	}
	code, out, errs := runIt(t, "schema", "--previous", schemaFile, "--current", schemaWith(t, "additive.sql"), "--declaration", filepath.Join(g6, "fixture.json"))
	want := fmt.Sprintf("note: this build's upgrade steps reach schema %d, not the declaration's 8: they are not judged", db.SchemaVersion)
	if code != exitOK || !strings.Contains(out, want) {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}
