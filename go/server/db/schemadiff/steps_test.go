// SPDX-License-Identifier: AGPL-3.0-or-later

package schemadiff

import (
	"context"
	"strings"
	"testing"
)

const (
	addTags     = "CREATE TABLE tags (id INTEGER NOT NULL PRIMARY KEY, name TEXT NOT NULL) STRICT;\nINSERT INTO tags (name) VALUES ('a row the step needs');\n"
	tagsTrigger = "CREATE TRIGGER tags_closed BEFORE INSERT ON tags BEGIN SELECT RAISE(ABORT, 'closed'); END;\n"
	// The way SQLite changes a column's CHECK: a new table, the rows
	// copied, the old one dropped, the new one renamed.
	stateWidened = "CREATE TABLE projects_new (\n  id TEXT NOT NULL PRIMARY KEY,\n  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),\n" +
		"  state TEXT NOT NULL DEFAULT 'active' CONSTRAINT projects_state_check CHECK (state IN ('active', 'archived', 'frozen')),\n  note TEXT,\n  UNIQUE (name)\n) STRICT;\n" +
		"INSERT INTO projects_new SELECT * FROM projects;\nDROP VIEW active_projects;\nDROP TABLE projects;\nALTER TABLE projects_new RENAME TO projects;\n" +
		"CREATE TRIGGER projects_no_rename BEFORE UPDATE OF name ON projects BEGIN SELECT RAISE(ABORT, 'no rename'); END;\n" +
		"CREATE VIEW active_projects AS SELECT id FROM projects WHERE state = 'active';\n"
)

func diffSteps(t *testing.T, steps []Step, newer string) ([]StepChanges, []Change) {
	t.Helper()
	judged, rest, err := DiffSteps(context.Background(), base, steps, newer)
	if err != nil {
		t.Fatal(err)
	}
	if len(judged) != len(steps) {
		t.Fatalf("%d steps judged of %d", len(judged), len(steps))
	}
	return judged, rest
}

// Each step is diffed against the schema just before it, and the steps give
// the schema they were run towards.
func TestDiffStepsDiffsEachStep(t *testing.T) {
	steps := []Step{{To: 2, CompatibleFrom: 1, SQL: addTags}, {To: 3, CompatibleFrom: 1, SQL: tagsTrigger}}
	judged, rest := diffSteps(t, steps, base+addTags+tagsTrigger)
	if len(rest) != 0 {
		t.Fatalf("the steps do not give the schema: %v", rest)
	}
	if c := judged[0].Changes; len(c) != 1 || c[0] != (Change{Additive, "table tags", "added"}) {
		t.Fatalf("step 2: %v", c)
	}
	if c := judged[1].Changes; len(c) != 1 || c[0].Class != Breaking || c[0].Object != "trigger tags_closed" {
		t.Fatalf("step 3: %v", c)
	}
	// Against the whole range, the trigger is on a new table: additive. Only
	// the step's own diff shows that schema 2's varlatchd trips over it.
	if c := diff(t, base, base+addTags+tagsTrigger); Breaks(c) {
		t.Fatalf("the whole range: %v", c)
	}
}

// A step that declares itself rollback-safe but breaks the schema before it
// fails, naming the step and the change; the same step declared not
// rollback-safe is a note.
func TestAMisdeclaredStepFails(t *testing.T) {
	steps := []Step{{To: 2, CompatibleFrom: 1, SQL: addTags}, {To: 3, CompatibleFrom: 1, SQL: tagsTrigger}}
	judged, _ := diffSteps(t, steps, base+addTags+tagsTrigger)
	problems, notes := JudgeSteps(judged)
	if len(problems) != 1 || !strings.Contains(problems[0], "the step to schema 3 declares compatibleFrom 1, so the varlatchd of schema 2 must still open the database after it, but breaking: trigger tags_closed: a new trigger on the existing table tags") ||
		!strings.Contains(problems[0], "raise the step's compatibleFrom to 3") {
		t.Fatalf("%q", problems)
	}
	if len(notes) != 2 || notes[0] != "the step to schema 2 (compatible from 1): 1 schema changes, rollback-safe" {
		t.Fatalf("%q", notes)
	}

	steps[1].CompatibleFrom = 3
	judged, _ = diffSteps(t, steps, base+addTags+tagsTrigger)
	problems, notes = JudgeSteps(judged)
	if len(problems) != 0 || len(notes) != 2 || notes[1] != "the step to schema 3 (compatible from 3): 1 schema changes, not rollback-safe" {
		t.Fatalf("%q %q", problems, notes)
	}
}

// A rollback-safe step's review change is for the release checklist, not a
// problem; a step that rebuilds a table is judged by what it leaves.
func TestARollbackSafeStepsReviewChangeIsANote(t *testing.T) {
	steps := []Step{{To: 2, CompatibleFrom: 1, SQL: stateWidened}}
	judged, rest := diffSteps(t, steps, strings.Replace(base, "('active', 'archived')", "('active', 'archived', 'frozen')", 1))
	if len(rest) != 0 {
		t.Fatalf("the rebuilt table: %v", rest)
	}
	problems, notes := JudgeSteps(judged)
	if len(problems) != 0 || len(notes) != 2 || !strings.HasPrefix(notes[1], "for the release checklist: the step to schema 2: review: column projects.state") {
		t.Fatalf("%q %q", problems, notes)
	}
}

// What the steps leave that is not the schema they were run towards is
// rest; a step that cannot run is an error naming it.
func TestDiffStepsRestAndErrors(t *testing.T) {
	_, rest := diffSteps(t, []Step{{To: 2, CompatibleFrom: 1, SQL: addTags}}, base+addTags+tagsTrigger)
	if len(rest) != 1 || rest[0].Object != "trigger tags_closed" {
		t.Fatalf("%v", rest)
	}
	_, rest = diffSteps(t, nil, base)
	if len(rest) != 0 {
		t.Fatalf("no steps: %v", rest)
	}
	_, _, err := DiffSteps(context.Background(), base, []Step{{To: 2, CompatibleFrom: 1, SQL: addTags}, {To: 3, CompatibleFrom: 1, SQL: "ALTER TABLE nowhere ADD COLUMN x TEXT;"}}, base)
	if err == nil || !strings.Contains(err.Error(), "the step to schema 3") {
		t.Fatalf("%v", err)
	}
}
