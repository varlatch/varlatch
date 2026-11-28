// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
)

// The PostgreSQL schema: db/testdata/pg-v0.22.0.json, generated from the
// TypeScript server's migrations (db/testdata/pgschema.mjs).

type pgDump struct {
	Ref        string    `json:"ref"`
	Migrations []string  `json:"migrations"`
	Tables     []pgTable `json:"tables"`
}

type pgTable struct {
	Name    string `json:"name"`
	Columns []struct {
		Name     string `json:"name"`
		Position int    `json:"position"`
		Type     string `json:"type"`
	} `json:"columns"`
	Constraints []struct {
		Type    string   `json:"type"`
		Columns []string `json:"columns"`
	} `json:"constraints"`
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func load(t *testing.T) *Manifest {
	t.Helper()
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func dump(t *testing.T) pgDump {
	t.Helper()
	var d pgDump
	readJSON(t, filepath.Join("..", "..", "db", "testdata", "pg-v0.22.0.json"), &d)
	return d
}

// checkPostgres: every PostgreSQL table and column, in the source's column
// order and with its type, and nothing else.
func checkPostgres(m *Manifest, d pgDump) []string {
	var errs []string
	if m.Source.Schema != d.Ref {
		errs = append(errs, "source.schema "+m.Source.Schema+", the dump is "+d.Ref)
	}
	if !slices.Equal(m.Source.Migrations, d.Migrations) {
		errs = append(errs, "source.migrations differ from the dump's")
	}
	seen := map[string]bool{}
	for _, pt := range d.Tables {
		seen[pt.Name] = true
		mt, ok := m.Table(pt.Name)
		if !ok {
			errs = append(errs, "table "+pt.Name+": not in the manifest")
			continue
		}
		cols := slices.Clone(pt.Columns)
		sort.Slice(cols, func(i, j int) bool { return cols[i].Position < cols[j].Position })
		if len(cols) != len(mt.Columns) {
			errs = append(errs, "table "+pt.Name+": the manifest's columns differ from PostgreSQL's")
		}
		for i, c := range cols {
			if i >= len(mt.Columns) {
				errs = append(errs, "table "+pt.Name+": column "+c.Name+" not in the manifest")
				continue
			}
			mc := mt.Columns[i]
			if mc.Source != c.Name || string(mc.Type) != c.Type {
				errs = append(errs, "table "+pt.Name+": column "+strconv.Itoa(i+1)+" is "+c.Name+" "+c.Type+", the manifest says "+mc.Source+" "+string(mc.Type))
			}
		}
		if mt.Action != LeftOut && !mt.PhysicalOrder && pt.Name != "audit_events" {
			for _, k := range pt.Constraints {
				if k.Type == "primary key" && !slices.Equal(k.Columns, mt.OrderBy) {
					errs = append(errs, "table "+pt.Name+": orderBy is not the primary key")
				}
			}
		}
	}
	for _, mt := range m.Tables {
		if !seen[mt.Source] {
			errs = append(errs, "table "+mt.Source+": in the manifest, not in PostgreSQL")
		}
	}
	return errs
}

// The mapping step 3 wrote: db/mapping.json.

type mappingFile struct {
	Tables map[string]struct {
		SQLite  string                     `json:"sqlite"`
		Dropped string                     `json:"dropped"`
		Columns map[string]json.RawMessage `json:"columns"`
	} `json:"tables"`
	Added struct {
		Tables map[string]string `json:"tables"`
	} `json:"added"`
}

func mappedColumn(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		SQLite string `json:"sqlite"`
	}
	_ = json.Unmarshal(raw, &o)
	return o.SQLite
}

// checkMapping: the manifest's targets are the mapping's, and the tables it
// leaves out are the ones the mapping dropped.
func checkMapping(m *Manifest, mp mappingFile) []string {
	var errs []string
	for _, mt := range m.Tables {
		tm, ok := mp.Tables[mt.Source]
		if !ok {
			errs = append(errs, "table "+mt.Source+": not in mapping.json")
			continue
		}
		if (mt.Action == LeftOut) != (tm.Dropped != "") {
			errs = append(errs, "table "+mt.Source+": left out in one of the manifest and mapping.json, not both")
			continue
		}
		if mt.Action == LeftOut {
			continue
		}
		if mt.Target != tm.SQLite {
			errs = append(errs, "table "+mt.Source+": target "+mt.Target+", mapping.json says "+tm.SQLite)
		}
		for _, c := range mt.Columns {
			if got := mappedColumn(tm.Columns[c.Source]); got != c.Target {
				errs = append(errs, "table "+mt.Source+": column "+c.Source+": target "+c.Target+", mapping.json says "+got)
			}
		}
	}
	for name := range mp.Added.Tables {
		if _, ok := m.TargetOnly.Tables[name]; !ok {
			errs = append(errs, "table "+name+": added by mapping.json, not target-only in the manifest")
		}
	}
	return errs
}

// The SQLite schema, as Init creates it from schema.sql.

type liteColumn struct{ name, typ string }

func readSQLite(t *testing.T) map[string][]liteColumn {
	t.Helper()
	ctx := context.Background()
	s, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := db.Init(ctx, s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	r := s.Reader()
	rows, err := r.QueryContext(ctx, "SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	out := map[string][]liteColumn{}
	for _, n := range names {
		cr, err := r.QueryContext(ctx, "SELECT name, type, hidden FROM pragma_table_xinfo(?) ORDER BY cid", n)
		if err != nil {
			t.Fatal(err)
		}
		for cr.Next() {
			var c liteColumn
			var hidden int
			if err := cr.Scan(&c.name, &c.typ, &hidden); err != nil {
				t.Fatal(err)
			}
			if hidden != 0 {
				t.Fatalf("%s.%s is a hidden or generated column, which the manifest has no rule for", n, c.name)
			}
			out[n] = append(out[n], c)
		}
		cr.Close()
	}
	return out
}

// liteType is the SQLite column type each PostgreSQL type maps to
// (mapping.json's types).
var liteType = map[canonical.Type]string{
	canonical.Text:        "TEXT",
	canonical.Timestamptz: "INTEGER",
	canonical.Integer:     "INTEGER",
	canonical.Bigint:      "INTEGER",
	canonical.Boolean:     "INTEGER",
	canonical.Jsonb:       "TEXT",
	canonical.TextArray:   "TEXT",
	canonical.Bytea:       "BLOB",
}

// checkSQLite: every SQLite table is a target or target-only, and every
// column of a target is one manifest column's target, of the type its
// PostgreSQL type maps to.
func checkSQLite(m *Manifest, lite map[string][]liteColumn) []string {
	var errs []string
	byTarget := map[string]Table{}
	for _, mt := range m.Tables {
		if mt.Target != "" {
			byTarget[mt.Target] = mt
		}
	}
	for name, cols := range lite {
		if _, ok := m.TargetOnly.Tables[name]; ok {
			continue
		}
		mt, ok := byTarget[name]
		if !ok {
			errs = append(errs, "SQLite table "+name+": no manifest table targets it, and it is not target-only")
			continue
		}
		mine := map[string]canonical.Type{}
		for _, c := range mt.Columns {
			mine[c.Target] = c.Type
		}
		for _, c := range cols {
			typ, ok := mine[c.name]
			if _, own := m.TargetOnly.Columns[name+"."+c.name]; own {
				if ok {
					errs = append(errs, "SQLite column "+name+"."+c.name+": target-only, yet a manifest column targets it")
				}
				continue
			}
			if !ok {
				errs = append(errs, "SQLite column "+name+"."+c.name+": no manifest column targets it")
				continue
			}
			if liteType[typ] != c.typ {
				errs = append(errs, "SQLite column "+name+"."+c.name+": "+c.typ+", but "+string(typ)+" maps to "+liteType[typ])
			}
			delete(mine, c.name)
		}
		for col := range mine {
			errs = append(errs, "table "+mt.Source+": target column "+name+"."+col+" is not in SQLite")
		}
	}
	for target := range byTarget {
		if _, ok := lite[target]; !ok {
			errs = append(errs, "target table "+target+" is not in SQLite")
		}
	}
	for name := range m.TargetOnly.Tables {
		if _, ok := lite[name]; !ok {
			errs = append(errs, "target-only table "+name+" is not in SQLite")
		}
	}
	for name := range m.TargetOnly.Columns {
		table, column, _ := strings.Cut(name, ".")
		if _, whole := m.TargetOnly.Tables[table]; whole {
			errs = append(errs, "target-only column "+name+": its whole table is target-only")
		}
		if !slices.ContainsFunc(lite[table], func(c liteColumn) bool { return c.name == column }) {
			errs = append(errs, "target-only column "+name+" is not in SQLite")
		}
	}
	return errs
}

func report(t *testing.T, what string, errs []string) {
	t.Helper()
	sort.Strings(errs)
	for _, e := range errs {
		t.Errorf("%s: %s", what, e)
	}
}

func TestManifestIsConsistent(t *testing.T) {
	m := load(t)
	if m.Target.SchemaVersion != db.SchemaVersion {
		t.Errorf("target.schemaVersion %d, schema.sql is %d", m.Target.SchemaVersion, db.SchemaVersion)
	}
}

func TestManifestCoversPostgres(t *testing.T) {
	report(t, "PostgreSQL", checkPostgres(load(t), dump(t)))
}

func TestManifestAgreesWithMapping(t *testing.T) {
	var mp mappingFile
	readJSON(t, filepath.Join("..", "..", "db", "mapping.json"), &mp)
	report(t, "mapping.json", checkMapping(load(t), mp))
}

func TestManifestCoversSQLite(t *testing.T) {
	report(t, "SQLite", checkSQLite(load(t), readSQLite(t)))
}

// TestANewColumnFails: a column added on either side, or a table, fails
// until the manifest accounts for it (go-step7.md 7.1's acceptance).
func TestANewColumnFails(t *testing.T) {
	m := load(t)
	d := dump(t)
	for i := range d.Tables {
		if d.Tables[i].Name == "grants" {
			c := d.Tables[i].Columns[0]
			c.Name, c.Position, c.Type = "added_later", 999, "text"
			d.Tables[i].Columns = append(d.Tables[i].Columns, c)
		}
	}
	d.Tables = append(d.Tables, pgTable{Name: "added_table"})
	errs := strings.Join(checkPostgres(m, d), "\n")
	for _, want := range []string{"added_later", "added_table"} {
		if !strings.Contains(errs, want) {
			t.Errorf("a PostgreSQL %s passed:\n%s", want, errs)
		}
	}

	lite := readSQLite(t)
	lite["grants"] = append(lite["grants"], liteColumn{"added_later", "TEXT"})
	lite["added_table"] = []liteColumn{{"id", "TEXT"}}
	errs = strings.Join(checkSQLite(m, lite), "\n")
	for _, want := range []string{"grants.added_later", "added_table"} {
		if !strings.Contains(errs, want) {
			t.Errorf("a SQLite %s passed:\n%s", want, errs)
		}
	}
}

// TestManifestRefusesItsOwnMistakes: Parse's self-checks catch an entry
// that leaves something out without a reason, a copied column without a
// target, and a type the encoding does not define.
func TestManifestRefusesItsOwnMistakes(t *testing.T) {
	for _, c := range []struct{ name, from, to string }{
		{"a table left out without a reason", `"precondition": "empty"`, `"precondition": "empty", "reason": ""`},
		{"a copied column without a target", `{"source": "id", "type": "text", "target": "id"}`, `{"source": "id", "type": "text"}`},
		{"an unknown type", `"type": "bytea"`, `"type": "money"`},
		{"an unknown member", `"version": 1,`, `"version": 1, "extra": true,`},
		{"no foreignKeys", `"foreignKeys": "The schema's`, `"foreignKeys": "", "x": "The schema's`},
		{"an empty leftOut", `{"source": "token", "type": "text", "target": "token_hash", "leftOut": "Better`, `{"source": "token", "type": "text", "target": "token_hash", "leftOut": "", "x": "Better`},
		{"physical order without its note", `"source": "approval_intent_challenges",`, `"source": "approval_intent_challenges", "physicalOrder": true,`},
	} {
		text := bytes.Replace(V1, []byte(c.from), []byte(c.to), 1)
		if bytes.Equal(text, V1) {
			t.Fatalf("%s: the replacement did not apply", c.name)
		}
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// TestTheTypeScriptCopiesAreTheSame: the TypeScript server's copies of the
// manifest and of the canonical vectors are these bytes. On main they are
// read from the working tree once the 0.22 line's 7.1 is forwarded here;
// until then, from origin/release/0.22 with git show, where that ref was
// fetched. With neither, the test says so and skips.
func TestTheTypeScriptCopiesAreTheSame(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	for _, c := range []struct{ ours, theirs string }{
		{"v1.json", "services/varlatchd/src/migration/manifest-v1.json"},
		{filepath.Join("..", "canonical", "testdata", "vectors.json"), "services/varlatchd/test/migration/canonical-vectors.json"},
	} {
		ours, err := os.ReadFile(c.ours)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.theirs)))
		where := c.theirs
		if os.IsNotExist(err) {
			where = "origin/release/0.22:" + c.theirs
			cmd := exec.Command("git", "show", where)
			cmd.Dir = root
			theirs, err = cmd.Output()
			if err != nil {
				t.Skipf("%s is not in the working tree and git show %s failed (%v): the 0.22 line's copies are compared once forwarded, or where that ref is fetched", c.theirs, where, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ours, theirs) {
			t.Errorf("%s differs from %s", where, c.ours)
		}
	}
}
