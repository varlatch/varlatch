// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The PostgreSQL side: testdata/pg-v0.22.0.json, written by
// testdata/pgschema.mjs from the v0.22.0 tag.

type pgDump struct {
	Ref       string                  `json:"ref"`
	Tables    []pgTable               `json:"tables"`
	Functions []struct{ Name string } `json:"functions"`
	Sequences []struct{ Name string } `json:"sequences"`
	Views     []struct{ Name string } `json:"views"`
	SeedRows  map[string]int          `json:"seedRows"`
}

type pgTable struct {
	Name    string `json:"name"`
	Columns []struct {
		Name    string  `json:"name"`
		Type    string  `json:"type"`
		NotNull bool    `json:"notNull"`
		Default *string `json:"default"`
	} `json:"columns"`
	Constraints []struct {
		Name       string   `json:"name"`
		Type       string   `json:"type"`
		Columns    []string `json:"columns"`
		RefTable   string   `json:"refTable"`
		RefColumns []string `json:"refColumns"`
		OnDelete   string   `json:"onDelete"`
		OnUpdate   string   `json:"onUpdate"`
		Index      string   `json:"index"`
		Definition string   `json:"definition"`
	} `json:"constraints"`
	Indexes []struct {
		Name           string `json:"name"`
		Unique         bool   `json:"unique"`
		FromConstraint bool   `json:"fromConstraint"`
		Keys           []struct {
			Key        string `json:"key"`
			Descending bool   `json:"descending"`
		} `json:"keys"`
		Predicate *string `json:"predicate"`
	} `json:"indexes"`
	Triggers []struct {
		Name     string `json:"name"`
		Function string `json:"function"`
	} `json:"triggers"`
}

// The mapping: mapping.json.

type mapping struct {
	Comment string `json:"comment"`
	Source  struct {
		Ref  string `json:"ref"`
		Dump string `json:"dump"`
	} `json:"source"`
	Types []struct {
		Postgres string `json:"postgres"`
		SQLite   string `json:"sqlite"`
		Rule     string `json:"rule"`
	} `json:"types"`
	Defaults []struct {
		Postgres string `json:"postgres"`
		SQLite   string `json:"sqlite"`
		Rule     string `json:"rule"`
	} `json:"defaults"`
	Tables    map[string]tableMap `json:"tables"`
	Functions map[string]target   `json:"functions"`
	SeedRows  map[string]target   `json:"seedRows"`
	Added     struct {
		Tables   map[string]string `json:"tables"`
		Triggers map[string]string `json:"triggers"`
	} `json:"added"`
}

type tableMap struct {
	SQLite      string            `json:"sqlite"`
	Dropped     string            `json:"dropped"`
	Note        string            `json:"note"`
	Columns     map[string]target `json:"columns"`
	Constraints map[string]target `json:"constraints"`
	Indexes     map[string]target `json:"indexes"`
	Triggers    map[string]target `json:"triggers"`
}

// target is a mapping entry: a plain string (the SQLite name, or a
// constraint's kind), or an object.
type target struct {
	SQLite    string   // name or kind
	SQLiteAll []string // a trigger or function's SQLite triggers
	Dropped   string
	Rewritten string
	Default   *string
	Note      string
}

func (t *target) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		t.SQLite = s
		return nil
	}
	var o struct {
		SQLite    json.RawMessage `json:"sqlite"`
		Dropped   string          `json:"dropped"`
		Rewritten string          `json:"rewritten"`
		Default   *string         `json:"default"`
		Note      string          `json:"note"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return err
	}
	*t = target{Dropped: o.Dropped, Rewritten: o.Rewritten, Default: o.Default, Note: o.Note}
	if len(o.SQLite) > 0 {
		if err := json.Unmarshal(o.SQLite, &t.SQLite); err != nil {
			if err := json.Unmarshal(o.SQLite, &t.SQLiteAll); err != nil {
				return err
			}
		}
	}
	if (t.SQLite == "" && t.SQLiteAll == nil) == (t.Dropped == "") {
		return fmt.Errorf("an entry needs exactly one of sqlite and dropped: %s", b)
	}
	return nil
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if path == "mapping.json" {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// The SQLite side, read from a database Init created.

type sqliteSchema struct {
	tables     map[string]*sqliteTable
	triggers   map[string]string // name -> table
	triggerSQL map[string]string // name -> CREATE TRIGGER statement
}

type sqliteTable struct {
	sql     string
	strict  bool
	noRowid bool // WITHOUT ROWID
	columns map[string]sqliteColumn
	pk      []string
	indexes map[string]sqliteIndex
	fks     []sqliteFK
	checks  map[string]string // named CHECK constraints: name -> expression
}

type sqliteColumn struct {
	typ     string
	notNull bool
	dflt    sql.NullString
}

type sqliteIndex struct {
	unique, partial bool
	origin          string // c (CREATE INDEX), u (UNIQUE), pk
	keys            []string
	desc            []bool
	predicate       string
}

type sqliteFK struct {
	table          string
	from, to       []string
	onDelete, onUp string
}

func readSQLite(t *testing.T, db *sql.DB) *sqliteSchema {
	t.Helper()
	ctx := context.Background()
	rows := func(q string, args ...any) *sql.Rows {
		t.Helper()
		r, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return r
	}
	s := &sqliteSchema{tables: map[string]*sqliteTable{}, triggers: map[string]string{}, triggerSQL: map[string]string{}}
	r := rows("SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name")
	idxSQL := map[string]string{}
	for r.Next() {
		var typ, name, tbl, text string
		if err := r.Scan(&typ, &name, &tbl, &text); err != nil {
			t.Fatal(err)
		}
		switch typ {
		case "table":
			s.tables[name] = &sqliteTable{sql: text, columns: map[string]sqliteColumn{}, indexes: map[string]sqliteIndex{}}
		case "trigger":
			s.triggers[name] = tbl
			s.triggerSQL[name] = text
		case "index":
			idxSQL[name] = text
		}
	}
	r.Close()
	r = rows("SELECT name, strict, wr FROM pragma_table_list WHERE schema = 'main' AND type = 'table'")
	for r.Next() {
		var name string
		var strict, wr bool
		if err := r.Scan(&name, &strict, &wr); err != nil {
			t.Fatal(err)
		}
		if tb := s.tables[name]; tb != nil {
			tb.strict, tb.noRowid = strict, wr
		}
	}
	r.Close()
	for name, tb := range s.tables {
		r := rows("SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_xinfo(?) ORDER BY cid", name)
		type pkcol struct {
			n    int
			name string
		}
		var pks []pkcol
		for r.Next() {
			var c sqliteColumn
			var cname string
			var pk int
			if err := r.Scan(&cname, &c.typ, &c.notNull, &c.dflt, &pk); err != nil {
				t.Fatal(err)
			}
			tb.columns[cname] = c
			if pk > 0 {
				pks = append(pks, pkcol{pk, cname})
			}
		}
		r.Close()
		sort.Slice(pks, func(i, j int) bool { return pks[i].n < pks[j].n })
		for _, p := range pks {
			tb.pk = append(tb.pk, p.name)
		}

		r = rows("SELECT name, \"unique\", origin, partial FROM pragma_index_list(?)", name)
		for r.Next() {
			var iname string
			var ix sqliteIndex
			if err := r.Scan(&iname, &ix.unique, &ix.origin, &ix.partial); err != nil {
				t.Fatal(err)
			}
			tb.indexes[iname] = ix
		}
		r.Close()
		for iname, ix := range tb.indexes {
			r := rows("SELECT coalesce(name, ''), desc FROM pragma_index_xinfo(?) WHERE key = 1 ORDER BY seqno", iname)
			for r.Next() {
				var k string
				var d bool
				if err := r.Scan(&k, &d); err != nil {
					t.Fatal(err)
				}
				ix.keys = append(ix.keys, k)
				ix.desc = append(ix.desc, d)
			}
			r.Close()
			if ix.partial {
				text := idxSQL[iname]
				i := strings.LastIndex(strings.ToUpper(text), " WHERE ")
				if i < 0 {
					t.Fatalf("index %s is partial, but its SQL has no WHERE: %s", iname, text)
				}
				ix.predicate = text[i+len(" WHERE "):]
			}
			tb.indexes[iname] = ix
		}

		r = rows("SELECT id, \"table\", \"from\", coalesce(\"to\", ''), on_update, on_delete FROM pragma_foreign_key_list(?) ORDER BY id, seq", name)
		byID := map[int]*sqliteFK{}
		var ids []int
		for r.Next() {
			var id int
			var ref, from, to, onUp, onDel string
			if err := r.Scan(&id, &ref, &from, &to, &onUp, &onDel); err != nil {
				t.Fatal(err)
			}
			fk, ok := byID[id]
			if !ok {
				fk = &sqliteFK{table: ref, onDelete: onDel, onUp: onUp}
				byID[id] = fk
				ids = append(ids, id)
			}
			fk.from = append(fk.from, from)
			fk.to = append(fk.to, to)
		}
		r.Close()
		for _, id := range ids {
			tb.fks = append(tb.fks, *byID[id])
		}
		tb.checks = namedChecks(t, name, tb.sql)
	}
	return s
}

var constraintCheck = regexp.MustCompile(`(?i)\bCONSTRAINT\s+(\w+)\s+CHECK\s*\(`)

// namedChecks finds every `CONSTRAINT <name> CHECK (<expression>)` in a
// table's SQL (comments removed).
func namedChecks(t *testing.T, table, text string) map[string]string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	text = b.String()
	out := map[string]string{}
	for _, m := range constraintCheck.FindAllStringSubmatchIndex(text, -1) {
		name := text[m[2]:m[3]]
		depth, start := 1, m[1]
		end := -1
		inString := false
		for i := start; i < len(text) && end < 0; i++ {
			switch c := text[i]; {
			case c == '\'':
				inString = !inString
			case inString:
			case c == '(':
				depth++
			case c == ')':
				depth--
				if depth == 0 {
					end = i
				}
			}
		}
		if end < 0 {
			t.Fatalf("%s: unbalanced CHECK %s", table, name)
		}
		if _, dup := out[name]; dup {
			t.Fatalf("%s: CHECK %s named twice", table, name)
		}
		out[name] = text[start:end]
	}
	return out
}

// Expressions (CHECK constraints, index predicates) are compared by
// structure: canonicalExpr in expr_test.go.

var pgCast = regexp.MustCompile(`::(text|numeric|integer|bigint|boolean)\b`)

// normalizeDefault brings a PostgreSQL default to SQLite's spelling.
func normalizeDefault(d string) string {
	d = pgCast.ReplaceAllString(d, "")
	switch d {
	case "now()":
		return "CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000"
	case "true":
		return "1"
	case "false":
		return "0"
	}
	return d
}

var pgOnDelete = map[string]string{"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}

func unquote(s string) string { return strings.Trim(s, `"`) }

func TestMapping(t *testing.T) {
	var dump pgDump
	var m mapping
	loadJSON(t, "mapping.json", &m)
	loadJSON(t, m.Source.Dump, &dump)
	if dump.Ref != m.Source.Ref {
		t.Fatalf("the dump is of %s, the mapping of %s", dump.Ref, m.Source.Ref)
	}
	if len(dump.Tables) == 0 {
		t.Fatal("the dump has no tables")
	}
	if len(dump.Sequences) > 0 || len(dump.Views) > 0 {
		t.Errorf("the dump has sequences or views, which the mapping does not cover: %v %v", dump.Sequences, dump.Views)
	}
	s := openDB(t)
	lite := readSQLite(t, s.Reader())

	types := map[string]string{}
	for _, ty := range m.Types {
		types[ty.Postgres] = ty.SQLite
	}

	// Every SQLite object that something in PostgreSQL maps to; whatever is
	// left at the end must be listed under "added".
	usedTables := map[string]bool{}
	usedColumns := map[string]bool{}  // table.column
	usedIndexes := map[string]bool{}  // table.index (named and automatic)
	usedFKs := map[string]bool{}      // table#n
	usedChecks := map[string]bool{}   // table.name
	usedTriggers := map[string]bool{} // name

	var intColumns []intColumn
	var arrayColumns [][2]string // table, column

	pgTables := map[string]bool{}
	for _, pt := range dump.Tables {
		pgTables[pt.Name] = true
		tm, ok := m.Tables[pt.Name]
		if !ok {
			t.Errorf("table %s: not in mapping.json", pt.Name)
			continue
		}
		if tm.Dropped != "" {
			if tm.SQLite != "" || tm.Columns != nil || tm.Constraints != nil || tm.Indexes != nil || tm.Triggers != nil {
				t.Errorf("table %s: dropped, but its entry maps parts of it", pt.Name)
			}
			if lite.tables[pt.Name] != nil {
				t.Errorf("table %s: dropped, but schema.sql has a table of that name", pt.Name)
			}
			continue
		}
		lt := lite.tables[tm.SQLite]
		if lt == nil {
			t.Errorf("table %s: maps to %s, which schema.sql does not create", pt.Name, tm.SQLite)
			continue
		}
		if !lt.strict {
			t.Errorf("table %s is not STRICT", tm.SQLite)
		}
		if usedTables[tm.SQLite] {
			t.Errorf("table %s: two PostgreSQL tables map to it", tm.SQLite)
		}
		usedTables[tm.SQLite] = true

		// Columns.
		col := func(pgName string) string {
			if c, ok := tm.Columns[pgName]; ok && c.SQLite != "" {
				return c.SQLite
			}
			return ""
		}
		seen := map[string]bool{}
		for _, pc := range pt.Columns {
			seen[pc.Name] = true
			cm, ok := tm.Columns[pc.Name]
			where := pt.Name + "." + pc.Name
			if !ok {
				t.Errorf("column %s: not in mapping.json", where)
				continue
			}
			if cm.Dropped != "" {
				if _, there := lt.columns[cm.SQLite]; there {
					t.Errorf("column %s: dropped, but %s has it", where, tm.SQLite)
				}
				continue
			}
			lc, ok := lt.columns[cm.SQLite]
			if !ok {
				t.Errorf("column %s: maps to %s.%s, which does not exist", where, tm.SQLite, cm.SQLite)
				continue
			}
			key := tm.SQLite + "." + cm.SQLite
			if usedColumns[key] {
				t.Errorf("column %s: two PostgreSQL columns map to it", key)
			}
			usedColumns[key] = true
			want, ok := types[pc.Type]
			if !ok {
				t.Errorf("column %s: type %s has no rule in mapping.json", where, pc.Type)
			} else if lc.typ != want {
				t.Errorf("column %s: %s should be %s by the type rule, is %s", where, pc.Type, want, lc.typ)
			}
			if _, ok := intRanges[pc.Type]; ok {
				intColumns = append(intColumns, intColumn{table: tm.SQLite, column: cm.SQLite, class: pc.Type})
			}
			if strings.HasSuffix(pc.Type, "[]") {
				arrayColumns = append(arrayColumns, [2]string{tm.SQLite, cm.SQLite})
			}
			if lc.notNull != pc.NotNull {
				t.Errorf("column %s: NOT NULL is %v in PostgreSQL, %v in SQLite", where, pc.NotNull, lc.notNull)
			}
			wantDefault := ""
			if pc.Default != nil {
				wantDefault = normalizeDefault(*pc.Default)
			}
			if cm.Default != nil {
				wantDefault = *cm.Default
			}
			if got := strings.TrimSpace(lc.dflt.String); got != wantDefault {
				t.Errorf("column %s: default %q, want %q", where, got, wantDefault)
			}
		}
		for name := range tm.Columns {
			if !seen[name] {
				t.Errorf("column %s.%s: in mapping.json, not in the dump", pt.Name, name)
			}
		}
		mapCols := func(cols []string) []string {
			out := make([]string, len(cols))
			for i, c := range cols {
				out[i] = col(unquote(c))
			}
			return out
		}

		// Constraints.
		seen = map[string]bool{}
		for _, pc := range pt.Constraints {
			seen[pc.Name] = true
			where := pt.Name + " constraint " + pc.Name
			cm, ok := tm.Constraints[pc.Name]
			if !ok {
				t.Errorf("%s: not in mapping.json", where)
				continue
			}
			if cm.Dropped != "" {
				continue
			}
			cols := mapCols(pc.Columns)
			switch kind := cm.SQLite; kind {
			case "primary key":
				if !slices.Equal(lt.pk, cols) {
					t.Errorf("%s: primary key (%v), SQLite's is (%v)", where, cols, lt.pk)
				}
				for name, ix := range lt.indexes {
					if ix.origin == "pk" {
						usedIndexes[tm.SQLite+"."+name] = true
					}
				}
			case "unique":
				if name := findUnique(lt, cols); name == "" {
					t.Errorf("%s: no unique, non-partial index on %s (%v)", where, tm.SQLite, cols)
				} else {
					usedIndexes[tm.SQLite+"."+name] = true
				}
			case "foreign key":
				ref := m.Tables[pc.RefTable]
				refCols := make([]string, len(pc.RefColumns))
				for i, c := range pc.RefColumns {
					refCols[i] = ref.Columns[unquote(c)].SQLite
				}
				found := false
				for i, fk := range lt.fks {
					if fk.table == ref.SQLite && slices.Equal(fk.from, cols) && slices.Equal(fk.to, refCols) {
						found = true
						usedFKs[fmt.Sprintf("%s#%d", tm.SQLite, i)] = true
						if fk.onDelete != pgOnDelete[pc.OnDelete] || fk.onUp != pgOnDelete[pc.OnUpdate] {
							t.Errorf("%s: ON DELETE %s ON UPDATE %s, SQLite has %s and %s", where,
								pgOnDelete[pc.OnDelete], pgOnDelete[pc.OnUpdate], fk.onDelete, fk.onUp)
						}
					}
				}
				if !found {
					t.Errorf("%s: no foreign key %s(%v) -> %s(%v)", where, tm.SQLite, cols, ref.SQLite, refCols)
				}
			case "check":
				expr, ok := lt.checks[pc.Name]
				if !ok {
					t.Errorf("%s: %s has no CONSTRAINT %s CHECK", where, tm.SQLite, pc.Name)
					continue
				}
				usedChecks[tm.SQLite+"."+pc.Name] = true
				if pc.Type != "check" {
					t.Errorf("%s: a %s constraint mapped to a CHECK", where, pc.Type)
				}
				if cm.Rewritten == "" {
					if a, b := canonicalExpr(t, where, pc.Definition), canonicalExpr(t, where, expr); a != b {
						t.Errorf("%s: the expressions differ (mark it rewritten, with the reason, if that is intended):\n  postgres: %s\n  sqlite:   %s", where, pc.Definition, expr)
					}
				}
			default:
				t.Errorf("%s: unknown SQLite form %q", where, kind)
			}
			if want := map[string]string{"primary key": "primary key", "unique": "unique", "foreign key": "foreign key", "check": "check"}[cm.SQLite]; want != pc.Type &&
				!(pc.Name == "audit_events_pkey" && cm.SQLite == "unique") {
				t.Errorf("%s: a %s constraint maps to %s", where, pc.Type, cm.SQLite)
			}
		}
		for name := range tm.Constraints {
			if !seen[name] {
				t.Errorf("%s constraint %s: in mapping.json, not in the dump", pt.Name, name)
			}
		}

		// Indexes (those behind a constraint are the constraint's).
		seen = map[string]bool{}
		for _, px := range pt.Indexes {
			if px.FromConstraint {
				continue
			}
			seen[px.Name] = true
			where := pt.Name + " index " + px.Name
			im, ok := tm.Indexes[px.Name]
			if !ok {
				t.Errorf("%s: not in mapping.json", where)
				continue
			}
			if im.Dropped != "" {
				if _, there := lt.indexes[px.Name]; there {
					t.Errorf("%s: dropped, but %s has an index of that name", where, tm.SQLite)
				}
				continue
			}
			keys := make([]string, len(px.Keys))
			desc := make([]bool, len(px.Keys))
			for i, k := range px.Keys {
				keys[i] = col(unquote(k.Key))
				desc[i] = k.Descending
			}
			if im.SQLite == "primary key" {
				if !px.Unique || px.Predicate != nil || !slices.Equal(lt.pk, keys) {
					t.Errorf("%s: maps to the primary key (%v), which is not the same", where, lt.pk)
				}
				continue
			}
			lx, ok := lt.indexes[im.SQLite]
			if !ok || lx.origin != "c" {
				t.Errorf("%s: maps to %s, which is not an index of %s", where, im.SQLite, tm.SQLite)
				continue
			}
			usedIndexes[tm.SQLite+"."+im.SQLite] = true
			if lx.unique != px.Unique || lx.partial != (px.Predicate != nil) || !slices.Equal(lx.keys, keys) || !slices.Equal(lx.desc, desc) {
				t.Errorf("%s: unique %v, partial %v, keys %v desc %v; SQLite's %s: unique %v, partial %v, keys %v desc %v", where,
					px.Unique, px.Predicate != nil, keys, desc, im.SQLite, lx.unique, lx.partial, lx.keys, lx.desc)
			}
			if px.Predicate != nil {
				if a, b := canonicalExpr(t, where, *px.Predicate), canonicalExpr(t, where, lx.predicate); a != b {
					t.Errorf("%s: predicates differ:\n  postgres: %s\n  sqlite:   %s", where, *px.Predicate, lx.predicate)
				}
			}
		}
		for name := range tm.Indexes {
			if !seen[name] {
				t.Errorf("%s index %s: in mapping.json, not in the dump (or behind a constraint)", pt.Name, name)
			}
		}

		// Triggers.
		seen = map[string]bool{}
		for _, pg := range pt.Triggers {
			seen[pg.Name] = true
			tg, ok := tm.Triggers[pg.Name]
			if !ok {
				t.Errorf("%s trigger %s: not in mapping.json", pt.Name, pg.Name)
				continue
			}
			if tg.Dropped != "" {
				continue
			}
			for _, name := range append(tg.SQLiteAll, tg.SQLite) {
				if name == "" {
					continue
				}
				if lite.triggers[name] != tm.SQLite {
					t.Errorf("%s trigger %s: maps to %s, which is not a trigger on %s", pt.Name, pg.Name, name, tm.SQLite)
				}
				usedTriggers[name] = true
			}
		}
		for name := range tm.Triggers {
			if !seen[name] {
				t.Errorf("%s trigger %s: in mapping.json, not in the dump", pt.Name, name)
			}
		}
	}
	for name := range m.Tables {
		if !pgTables[name] {
			t.Errorf("table %s: in mapping.json, not in the dump", name)
		}
	}

	// PostgreSQL functions.
	pgFunctions := map[string]bool{}
	for _, f := range dump.Functions {
		pgFunctions[f.Name] = true
		fm, ok := m.Functions[f.Name]
		if !ok {
			t.Errorf("function %s: not in mapping.json", f.Name)
			continue
		}
		for _, name := range append(fm.SQLiteAll, fm.SQLite) {
			if name != "" && lite.triggers[name] == "" {
				t.Errorf("function %s: maps to trigger %s, which does not exist", f.Name, name)
			}
		}
	}
	for name := range m.Functions {
		if !pgFunctions[name] {
			t.Errorf("function %s: in mapping.json, not in the dump", name)
		}
	}

	// Rows a fresh installation starts with.
	for table, n := range dump.SeedRows {
		sm, ok := m.SeedRows[table]
		if !ok {
			t.Errorf("seed rows of %s: not in mapping.json", table)
			continue
		}
		if sm.Dropped != "" {
			continue
		}
		var got int
		if err := s.Reader().QueryRow("SELECT count(*) FROM " + sm.SQLite).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != n {
			t.Errorf("seed rows: %s has %d after Init, PostgreSQL's %s %d", sm.SQLite, got, table, n)
		}
	}
	for table := range m.SeedRows {
		if _, ok := dump.SeedRows[table]; !ok {
			t.Errorf("seed rows of %s: in mapping.json, not in the dump", table)
		}
	}

	// The integer range checks (type rule) and the array element triggers.
	for _, ic := range intColumns {
		checkIntRange(t, s.Reader(), lite.tables[ic.table], ic)
		usedChecks[ic.table+"."+rangePrefix[ic.class]+ic.column] = true
	}
	for _, ac := range arrayColumns {
		for _, event := range []string{"insert", "update"} {
			name := ac[0] + "_text_arrays_" + event
			if lite.triggers[name] != ac[0] || !strings.Contains(lite.triggerSQL[name], "NEW."+ac[1]+")") {
				t.Errorf("column %s.%s (an array): no trigger %s checking its elements", ac[0], ac[1], name)
			}
		}
	}

	// Whatever SQLite has beyond the image of PostgreSQL is listed as added.
	for name, lt := range lite.tables {
		if _, added := m.Added.Tables[name]; added {
			if usedTables[name] {
				t.Errorf("table %s: listed as added, but a PostgreSQL table maps to it", name)
			}
			continue
		}
		if !usedTables[name] {
			t.Errorf("table %s: no PostgreSQL table maps to it, and it is not listed as added", name)
			continue
		}
		for c := range lt.columns {
			if !usedColumns[name+"."+c] {
				t.Errorf("column %s.%s: no PostgreSQL column maps to it", name, c)
			}
		}
		for ix, info := range lt.indexes {
			if !usedIndexes[name+"."+ix] {
				t.Errorf("index %s (%s on %s): nothing in PostgreSQL maps to it", ix, info.origin, name)
			}
		}
		for i := range lt.fks {
			if !usedFKs[fmt.Sprintf("%s#%d", name, i)] {
				t.Errorf("foreign key %s -> %s: no PostgreSQL foreign key maps to it", name, lt.fks[i].table)
			}
		}
		for c := range lt.checks {
			if !usedChecks[name+"."+c] {
				t.Errorf("CHECK %s on %s: no PostgreSQL constraint maps to it", c, name)
			}
		}
	}
	for name := range m.Added.Tables {
		if lite.tables[name] == nil {
			t.Errorf("table %s: listed as added, but schema.sql has no such table", name)
		}
	}
	// A table guarded against REPLACE has no hidden rowid to collide on:
	// either its primary key is the rowid (one INTEGER column) or it is
	// WITHOUT ROWID.
	for name, tbl := range lite.triggers {
		if !strings.HasSuffix(name, "_no_replace_insert") {
			continue
		}
		lt := lite.tables[tbl]
		rowidKey := len(lt.pk) == 1 && lt.columns[lt.pk[0]].typ == "INTEGER"
		if !rowidKey && !lt.noRowid {
			t.Errorf("table %s: guarded against REPLACE, with a hidden rowid its guards do not see; make it WITHOUT ROWID", tbl)
		}
	}
	for name := range lite.triggers {
		_, added := m.Added.Triggers[name]
		if added == usedTriggers[name] {
			t.Errorf("trigger %s: must be either mapped from PostgreSQL or listed as added, not both or neither", name)
		}
	}
	for name := range m.Added.Triggers {
		if lite.triggers[name] == "" {
			t.Errorf("trigger %s: listed as added, but schema.sql has no such trigger", name)
		}
	}
}

func findUnique(lt *sqliteTable, cols []string) string {
	for name, ix := range lt.indexes {
		if ix.unique && !ix.partial && slices.Equal(ix.keys, cols) {
			return name
		}
	}
	if slices.Equal(lt.pk, cols) {
		for name, ix := range lt.indexes {
			if ix.origin == "pk" {
				return name
			}
		}
		return "rowid"
	}
	return ""
}

// The sqlc overrides map exactly the boolean columns (not the singletons,
// whose value is always 1) to bool, or sql.NullBool when nullable.
func TestSQLCBooleanOverrides(t *testing.T) {
	var dump pgDump
	var m mapping
	loadJSON(t, "mapping.json", &m)
	loadJSON(t, m.Source.Dump, &dump)
	var cfg struct {
		SQL []struct {
			Gen struct {
				Go struct {
					Overrides []struct {
						Column string          `json:"column"`
						GoType json.RawMessage `json:"go_type"`
					} `json:"overrides"`
				} `json:"go"`
			} `json:"gen"`
		} `json:"sql"`
	}
	loadJSON(t, "sqlc.json", &cfg)
	got := map[string]string{}
	for _, o := range cfg.SQL[0].Gen.Go.Overrides {
		got[o.Column] = string(o.GoType)
	}
	want := map[string]string{}
	for _, pt := range dump.Tables {
		tm := m.Tables[pt.Name]
		if tm.Dropped != "" {
			continue
		}
		for _, c := range pt.Columns {
			if c.Type != "boolean" || c.Name == "singleton" {
				continue
			}
			goType := `"bool"`
			if !c.NotNull {
				goType = `{"import":"database/sql","type":"NullBool"}`
			}
			want[tm.SQLite+"."+tm.Columns[c.Name].SQLite] = goType
		}
	}
	for col, w := range want {
		g, ok := got[col]
		var compact strings.Builder
		for _, r := range g {
			if r != ' ' && r != '\n' {
				compact.WriteRune(r)
			}
		}
		if !ok || compact.String() != w {
			t.Errorf("sqlc.json: %s should be overridden to %s, is %q", col, w, g)
		}
	}
	for col := range got {
		if _, ok := want[col]; !ok {
			t.Errorf("sqlc.json: %s is overridden but is not a boolean column", col)
		}
	}
}

// intRanges are the PostgreSQL integer types SQLite's 64-bit INTEGER
// widens, with their range (the type rule int4_<column>).
var intRanges = map[string][2]int64{
	"smallint": {-32768, 32767},
	"integer":  {-2147483648, 2147483647},
}

// rangePrefix names a column's range check: int4_<column>, int2_<column>.
var rangePrefix = map[string]string{"smallint": "int2_", "integer": "int4_"}

type intColumn struct{ table, column, class string }

// checkIntRange requires a column's checks to keep PostgreSQL's range: one
// past either end is refused. The range check (int4_<column>) must accept
// both ends, may only bound a side PostgreSQL's own checks leave open, and
// must not exist when they bound both.
func checkIntRange(t *testing.T, db *sql.DB, lt *sqliteTable, ic intColumn) {
	t.Helper()
	where := ic.table + "." + ic.column
	lo, hi := intRanges[ic.class][0], intRanges[ic.class][1]
	var own []string // the column's checks from PostgreSQL
	for name, expr := range lt.checks {
		if !strings.HasPrefix(name, "int4_") && !strings.HasPrefix(name, "int2_") && onlyColumn(expr, ic.column) {
			own = append(own, expr)
		}
	}
	rangeName := rangePrefix[ic.class] + ic.column
	rangeCheck, hasRange := lt.checks[rangeName]
	if hasRange && !onlyColumn(rangeCheck, ic.column) {
		t.Errorf("%s: %s reads other columns", where, rangeName)
		return
	}
	accepts := func(exprs []string, v int64) bool {
		t.Helper()
		q := "SELECT 1"
		for _, e := range exprs {
			q += " AND coalesce((" + e + "), 1)"
		}
		var ok bool
		if err := db.QueryRow("SELECT ("+q+") FROM (SELECT ? AS "+ic.column+")", v).Scan(&ok); err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		return ok
	}
	all := own
	if hasRange {
		all = append(slices.Clone(own), rangeCheck)
	}
	for _, v := range []int64{lo - 1, hi + 1} {
		if accepts(all, v) {
			t.Errorf("%s: %d is accepted, outside PostgreSQL's %s", where, v, ic.class)
		}
	}
	if !hasRange {
		return
	}
	if !accepts([]string{rangeCheck}, lo) || !accepts([]string{rangeCheck}, hi) {
		t.Errorf("%s: %s refuses a value of PostgreSQL's %s range", where, rangeName, ic.class)
	}
	needed := false
	for _, v := range []int64{lo - 1, hi + 1} {
		if accepts(own, v) {
			needed = true
		} else if !accepts([]string{rangeCheck}, v) {
			t.Errorf("%s: %s bounds a side PostgreSQL's own check already bounds (%d)", where, rangeName, v)
		}
	}
	if !needed {
		t.Errorf("%s: %s is redundant: PostgreSQL's checks already bound both sides", where, rangeName)
	}
}

// onlyColumn reports whether an expression reads exactly one column, col.
func onlyColumn(expr, col string) bool {
	toks, err := tokenize(expr)
	if err != nil {
		return false
	}
	seen := false
	for i, tk := range toks {
		if tk.kind != tokIdent || (i+1 < len(toks) && toks[i+1].kind == tokOp && toks[i+1].text == "(") {
			continue
		}
		if tk.text != col {
			return false
		}
		seen = true
	}
	return seen
}
