// SPDX-License-Identifier: AGPL-3.0-or-later

package schemadiff

import (
	"context"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/db"
)

const base = `
-- a comment that is not part of the schema
CREATE TABLE projects (
  id TEXT NOT NULL PRIMARY KEY, -- the key
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  state TEXT NOT NULL DEFAULT 'active' CONSTRAINT projects_state_check CHECK (state IN ('active', 'archived')),
  note TEXT,
  UNIQUE (name)
) STRICT;
CREATE TABLE values_ (
  id INTEGER NOT NULL PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
  body BLOB NOT NULL
) STRICT;
CREATE INDEX values_project ON values_ (project_id);
CREATE TRIGGER projects_no_rename BEFORE UPDATE OF name ON projects BEGIN SELECT RAISE(ABORT, 'no rename'); END;
CREATE VIEW active_projects AS SELECT id FROM projects WHERE state = 'active';
`

func diff(t *testing.T, older, newer string) []Change {
	t.Helper()
	changes, err := Diff(context.Background(), older, newer)
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

func TestTheSameSchemaHasNoChanges(t *testing.T) {
	if c := diff(t, base, base); len(c) != 0 {
		t.Fatalf("%v", c)
	}
	// Spacing, comments, case and quoting are not changes.
	reformatted := strings.NewReplacer("CREATE TABLE projects (", `create table "projects"(`, "  ", "\t", "-- the key", "/* the key */").Replace(base)
	if c := diff(t, base, reformatted); len(c) != 0 {
		t.Fatalf("a reformatted schema: %v", c)
	}
}

// varlatchd's own schema loads, and every table's columns are found.
func TestVarlatchdsSchema(t *testing.T) {
	if c := diff(t, db.Schema(), db.Schema()); len(c) != 0 {
		t.Fatalf("%v", c)
	}
	s, err := load(context.Background(), db.Schema())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.tables) < 50 || len(s.objects["trigger"]) == 0 || len(s.objects["index"]) == 0 {
		t.Fatalf("%d tables, %d triggers, %d indexes", len(s.tables), len(s.objects["trigger"]), len(s.objects["index"]))
	}
}

func TestChangesAreClassified(t *testing.T) {
	for _, c := range []struct {
		name   string
		newer  string // statements run after base
		class  Class
		object string
		what   string
	}{
		// Additive.
		{"a new table", "CREATE TABLE tags (id INTEGER NOT NULL PRIMARY KEY, name TEXT NOT NULL) STRICT;", Additive, "table tags", "added"},
		{"a nullable column", "ALTER TABLE projects ADD COLUMN description TEXT;", Additive, "column projects.description", "added"},
		{"a NOT NULL column with a default", "ALTER TABLE projects ADD COLUMN weight INTEGER NOT NULL DEFAULT 0;", Additive, "column projects.weight", "added"},
		{"a non-unique index removed", "DROP INDEX values_project;", Additive, "index values_project", "removed: the previous release stays correct, only slower"},

		// Review.
		{"a nullable reference on an existing table", "ALTER TABLE values_ ADD COLUMN moved_to TEXT REFERENCES projects (id);", Review, "column values_.moved_to",
			"a new reference on an existing table: SQLite enforces it for the previous release's deletes and updates too"},
		{"a non-unique index", "CREATE INDEX projects_state ON projects (state);", Additive, "index projects_state", "added"},
		{"a view", "CREATE VIEW all_projects AS SELECT id FROM projects;", Additive, "view all_projects", "added"},
		{"a trigger on a new table", "CREATE TABLE t2 (id INTEGER PRIMARY KEY) STRICT; CREATE TRIGGER t2_guard BEFORE DELETE ON t2 BEGIN SELECT RAISE(ABORT, 'x'); END;", Additive, "trigger t2_guard", "added"},

		// Breaking.
		{"a removed table", "DROP VIEW active_projects; DROP TABLE values_;", Breaking, "table values_", "removed"},
		{"a removed column", "ALTER TABLE projects DROP COLUMN note;", Breaking, "column projects.note", "removed (or renamed)"},
		{"a renamed column", "ALTER TABLE projects RENAME COLUMN note TO remark;", Breaking, "column projects.note", "removed (or renamed)"},
		{"a renamed table", "ALTER TABLE values_ RENAME TO items;", Breaking, "table values_", "removed"},
		{"a new unique index", "CREATE UNIQUE INDEX values_body ON values_ (body);", Breaking, "index values_body", "a new unique index on the existing table values_"},
		{"a new trigger on an existing table", "CREATE TRIGGER values_frozen BEFORE INSERT ON values_ BEGIN SELECT RAISE(ABORT, 'frozen'); END;", Breaking, "trigger values_frozen", "a new trigger on the existing table values_: it may refuse or change the previous release's writes"},
		{"a removed trigger", "DROP TRIGGER projects_no_rename;", Breaking, "trigger projects_no_rename", "removed"},
		{"a changed view", "DROP VIEW active_projects; CREATE VIEW active_projects AS SELECT id, name FROM projects WHERE state = 'active';", Breaking, "view active_projects", "changed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			changes := diff(t, base, base+c.newer)
			found := false
			for _, ch := range changes {
				if ch.Class == c.class && ch.Object == c.object && ch.What == c.what {
					found = true
				}
				if c.class != Breaking && ch.Class == Breaking {
					t.Errorf("an additive change also gave %v", ch)
				}
			}
			if !found {
				t.Fatalf("want %s: %s: %s; got %v", c.class, c.object, c.what, changes)
			}
			if Breaks(changes) != (c.class == Breaking) {
				t.Fatalf("Breaks = %v for %v", Breaks(changes), changes)
			}
		})
	}
}

// Changes SQLite makes only by rebuilding a table: the newer schema is
// written out as a whole.
func TestRebuiltTables(t *testing.T) {
	rebuilt := func(from, to string) string {
		if !strings.Contains(base, from) {
			t.Fatalf("base has no %q", from)
		}
		return strings.Replace(base, from, to, 1)
	}
	for _, c := range []struct {
		name, from, to string
		class          Class
		what           string
	}{
		{"an enumeration gains a value", "IN ('active', 'archived')", "IN ('active', 'archived', 'frozen')", Review,
			"its CHECK (... IN (...)) gains values: the previous release must reject them or handle them safely"},
		{"an enumeration loses a value", "IN ('active', 'archived')", "IN ('active')", Breaking, ""},
		{"an enumeration's value replaced", "IN ('active', 'archived')", "IN ('active', 'retired', 'gone')", Breaking, ""},
		{"a check narrowed", "BETWEEN 1 AND 64", "BETWEEN 1 AND 32", Breaking, ""},
		{"a column made NOT NULL", "note TEXT,", "note TEXT NOT NULL DEFAULT '',", Breaking, ""},
		{"a default changed", "DEFAULT 'active'", "DEFAULT 'archived'", Breaking, ""},
		{"a column's type changed", "body BLOB NOT NULL", "body TEXT NOT NULL", Breaking, ""},
		{"a new table constraint", "UNIQUE (name)\n) STRICT;", "UNIQUE (name),\n  CHECK (note IS NULL OR length(note) < 10)\n) STRICT;", Breaking, "a new table constraint: check ( note is null or length ( note ) < 10 )"},
		{"a table constraint removed", "  note TEXT,\n  UNIQUE (name)\n", "  note TEXT\n", Breaking, "a table constraint removed or changed: unique ( name )"},
		{"STRICT dropped", "  body BLOB NOT NULL\n) STRICT;", "  body BLOB NOT NULL\n);", Breaking, `its options changed from "strict" to ""`},
		{"a new NOT NULL column without a default", "  note TEXT,\n", "  note TEXT,\n  owner TEXT NOT NULL,\n", Breaking, "a new NOT NULL column without a default: the previous release's inserts fail"},
		{"a new unique column", "  note TEXT,\n", "  note TEXT,\n  slug TEXT UNIQUE,\n", Breaking, "a new unique column"},
	} {
		t.Run(c.name, func(t *testing.T) {
			changes := diff(t, base, rebuilt(c.from, c.to))
			if len(changes) == 0 {
				t.Fatal("no change found")
			}
			if changes[0].Class != c.class {
				t.Fatalf("want %s first; got %v", c.class, changes)
			}
			if c.what != "" && changes[0].What != c.what {
				t.Fatalf("want %q; got %v", c.what, changes)
			}
		})
	}
}

// A unique index or constraint the older schema has and the newer one does
// not is breaking: the previous release's ON CONFLICT upserts need it.
func TestRemovedUniqueness(t *testing.T) {
	withIndex := base + "CREATE UNIQUE INDEX values_body ON values_ (body);"
	changes := diff(t, withIndex, base)
	if len(changes) != 1 || changes[0].Class != Breaking || changes[0].Object != "index values_body" ||
		changes[0].What != "a unique index removed: the previous release's upserts (ON CONFLICT) and its guarantees may need it" {
		t.Fatalf("a unique index removed: %v", changes)
	}
	withColumn := strings.Replace(base, "note TEXT,", "note TEXT UNIQUE,", 1)
	if changes := diff(t, withColumn, base); !Breaks(changes) {
		t.Fatalf("a column's UNIQUE removed: %v", changes)
	}
}

func TestOrderAndText(t *testing.T) {
	changes := diff(t, base, base+"CREATE TABLE tags (id INTEGER PRIMARY KEY) STRICT; ALTER TABLE projects DROP COLUMN note;")
	if len(changes) != 2 || changes[0].Class != Breaking || changes[1].Class != Additive {
		t.Fatalf("breaking first: %v", changes)
	}
	if got := changes[0].String(); got != "breaking: column projects.note: removed (or renamed)" {
		t.Fatalf("%q", got)
	}
}

func TestSchemasThatDoNotLoad(t *testing.T) {
	if _, err := Diff(context.Background(), base, "CREATE TABLE ("); err == nil || !strings.Contains(err.Error(), "the newer schema") {
		t.Fatalf("%v", err)
	}
	if _, err := Diff(context.Background(), "nonsense", base); err == nil || !strings.Contains(err.Error(), "the older schema") {
		t.Fatalf("%v", err)
	}
}

func TestTokenize(t *testing.T) {
	toks, err := tokenize(`CREATE TABLE "A b"(x TEXT DEFAULT 'it''s -- not a comment' /* c */, [Y] INT) -- end`)
	if err != nil {
		t.Fatal(err)
	}
	want := `create table "A b" ( x text default 'it''s -- not a comment' , y int )`
	if join(toks) != want {
		t.Fatalf("%q", join(toks))
	}
	for _, bad := range []string{"'open", `"open`, "/* open"} {
		if _, err := tokenize(bad); err == nil {
			t.Errorf("%q tokenized", bad)
		}
	}
}
