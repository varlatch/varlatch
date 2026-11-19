// SPDX-License-Identifier: AGPL-3.0-or-later

// Package schemadiff compares two versions of varlatchd's SQLite schema and
// says which changes a rollback-safe release may make (ADR-0059 Decision 8,
// G6; internal docs/design/go-step6.md decision 5).
//
// A rollback-safe release only adds: the previous release's varlatchd must
// read the database, write to it and enforce every rule stored in it. Of
// Decision 8's list, this check covers the part the schema shows:
//
//   - additive: a new table, view or non-unique index; a new column that is
//     nullable or has a default, and is neither a key nor unique; a trigger
//     on a new table;
//   - review: a column's CHECK (x IN (...)) that only gains values, a new
//     value in an existing enumeration, which is rollback-safe only if the
//     previous release rejects the value or handles it safely (G6's writes
//     of every new kind and the release checklist decide);
//   - breaking: anything removed, renamed or changed; a new NOT NULL
//     column without a default, a new key or unique column; a new table
//     constraint, unique index or trigger on an existing table (a new
//     restriction, which the previous release would either trip over or
//     not know it must keep); a table's STRICT or WITHOUT ROWID changed.
//
// What the schema does not show (an envelope format or its associated data,
// a value the previous release misreads, a restriction kept in code) is
// left to G6's run and the release checklist.
//
// Both schemas are executed into in-memory databases, so the comparison is
// of what SQLite stored (sqlite_schema and the table pragmas), with
// comments and spacing taken out, not of the files' text.
package schemadiff

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// Class is how a change bears on rollback safety.
type Class string

const (
	Additive Class = "additive"
	Review   Class = "review"
	Breaking Class = "breaking"
)

// Change is one difference between the two schemas.
type Change struct {
	Class  Class  `json:"class"`
	Object string `json:"object"` // "table t", "column t.c", "index i", "trigger g", "view v"
	What   string `json:"what"`
}

func (c Change) String() string { return fmt.Sprintf("%s: %s: %s", c.Class, c.Object, c.What) }

// Breaks reports whether any change is breaking.
func Breaks(changes []Change) bool {
	return slices.ContainsFunc(changes, func(c Change) bool { return c.Class == Breaking })
}

// Diff returns the changes from the schema older creates to the one newer
// creates, in a stable order (breaking first, then review, then additive;
// by object within each).
func Diff(ctx context.Context, older, newer string) ([]Change, error) {
	a, err := load(ctx, older)
	if err != nil {
		return nil, fmt.Errorf("schemadiff: the older schema: %w", err)
	}
	b, err := load(ctx, newer)
	if err != nil {
		return nil, fmt.Errorf("schemadiff: the newer schema: %w", err)
	}
	var out []Change
	add := func(class Class, object, what string) { out = append(out, Change{class, object, what}) }

	for _, name := range keys(a.tables) {
		ta, tb := a.tables[name], b.tables[name]
		if tb == nil {
			add(Breaking, "table "+name, "removed")
			continue
		}
		diffTable(ta, tb, add)
	}
	for _, name := range keys(b.tables) {
		if a.tables[name] == nil {
			add(Additive, "table "+name, "added")
		}
	}

	for _, kind := range []string{"index", "trigger", "view"} {
		oa, ob := a.objects[kind], b.objects[kind]
		for _, name := range keys(oa) {
			x, y := oa[name], ob[name]
			switch {
			case y == nil:
				add(Breaking, kind+" "+name, "removed")
			case x.sql != y.sql:
				add(Breaking, kind+" "+name, "changed")
			}
		}
		for _, name := range keys(ob) {
			if oa[name] != nil {
				continue
			}
			y := ob[name]
			_, existing := a.tables[y.table]
			switch {
			case kind == "index" && y.unique && existing:
				add(Breaking, kind+" "+name, "a new unique index on the existing table "+y.table)
			case kind == "trigger" && existing:
				add(Breaking, kind+" "+name, "a new trigger on the existing table "+y.table+": it may refuse or change the previous release's writes")
			default:
				add(Additive, kind+" "+name, "added")
			}
		}
	}

	rank := map[Class]int{Breaking: 0, Review: 1, Additive: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Class] != rank[out[j].Class] {
			return rank[out[i].Class] < rank[out[j].Class]
		}
		return out[i].Object < out[j].Object
	})
	return out, nil
}

type table struct {
	name        string
	options     string            // after the closing parenthesis: STRICT, WITHOUT ROWID
	columns     map[string]column // by lower-cased name
	order       []string
	constraints map[string]bool // normalized table constraints
}

type column struct {
	name    string
	toks    []string // the definition's tokens, its name lower-cased first
	def     string   // the tokens joined
	notNull bool
	hasDflt bool
	pk      bool
}

type object struct {
	sql    string // normalized
	table  string
	unique bool
}

type schema struct {
	tables  map[string]*table
	objects map[string]map[string]*object // kind -> name -> object
}

func diffTable(a, b *table, add func(Class, string, string)) {
	if a.options != b.options {
		add(Breaking, "table "+a.name, fmt.Sprintf("its options changed from %q to %q", a.options, b.options))
	}
	for _, key := range a.order {
		ca := a.columns[key]
		cb, ok := b.columns[key]
		switch {
		case !ok:
			add(Breaking, "column "+a.name+"."+ca.name, "removed (or renamed)")
		case ca.def != cb.def:
			if widened(ca.toks, cb.toks) {
				add(Review, "column "+a.name+"."+ca.name, "its CHECK (... IN (...)) gains values: the previous release must reject them or handle them safely")
			} else {
				add(Breaking, "column "+a.name+"."+ca.name, fmt.Sprintf("changed from %q to %q", ca.def, cb.def))
			}
		}
	}
	for _, key := range b.order {
		if _, ok := a.columns[key]; ok {
			continue
		}
		c := b.columns[key]
		obj := "column " + b.name + "." + c.name
		switch {
		case c.pk:
			add(Breaking, obj, "a new key column")
		case c.notNull && !c.hasDflt:
			add(Breaking, obj, "a new NOT NULL column without a default: the previous release's inserts fail")
		case slices.Contains(c.toks, "unique"):
			add(Breaking, obj, "a new unique column")
		default:
			add(Additive, obj, "added")
		}
	}
	for _, k := range keys(a.constraints) {
		if !b.constraints[k] {
			add(Breaking, "table "+a.name, "a table constraint removed or changed: "+k)
		}
	}
	for _, k := range keys(b.constraints) {
		if !a.constraints[k] {
			add(Breaking, "table "+a.name, "a new table constraint: "+k)
		}
	}
}

func load(ctx context.Context, ddl string) (*schema, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, ddl); err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY type, name")
	if err != nil {
		return nil, err
	}
	type entry struct{ kind, name, table, sql string }
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.kind, &e.name, &e.table, &e.sql); err != nil {
			rows.Close()
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	s := &schema{tables: map[string]*table{}, objects: map[string]map[string]*object{"index": {}, "trigger": {}, "view": {}}}
	for _, e := range entries {
		if e.kind != "table" {
			toks, err := tokenize(e.sql)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", e.kind, e.name, err)
			}
			norm := join(toks)
			s.objects[e.kind][strings.ToLower(e.name)] = &object{sql: norm, table: strings.ToLower(e.table),
				unique: e.kind == "index" && strings.HasPrefix(norm, "create unique index")}
			continue
		}
		t, err := parseTable(e.name, e.sql)
		if err != nil {
			return nil, fmt.Errorf("table %s: %w", e.name, err)
		}
		if err := t.readPragmas(ctx, conn); err != nil {
			return nil, fmt.Errorf("table %s: %w", e.name, err)
		}
		s.tables[strings.ToLower(e.name)] = t
	}
	return s, nil
}

// readPragmas takes each column's NOT NULL, default and key from SQLite,
// not from parsing.
func (t *table) readPragmas(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "SELECT name, \"notnull\", dflt_value IS NOT NULL, pk FROM pragma_table_xinfo(?)", t.name)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name string
		var notNull, dflt bool
		var pk int
		if err := rows.Scan(&name, &notNull, &dflt, &pk); err != nil {
			return err
		}
		c, ok := t.columns[strings.ToLower(name)]
		if !ok {
			return fmt.Errorf("SQLite has a column %s the definition does not show", name)
		}
		c.notNull, c.hasDflt, c.pk = notNull, dflt, pk > 0
		t.columns[strings.ToLower(name)] = c
		seen++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if seen != len(t.columns) {
		return fmt.Errorf("%d columns parsed, %d in SQLite", len(t.columns), seen)
	}
	return nil
}

// parseTable splits CREATE TABLE's definition list into column definitions
// and table constraints.
func parseTable(name, ddl string) (*table, error) {
	toks, err := tokenize(ddl)
	if err != nil {
		return nil, err
	}
	open := slices.Index(toks, "(")
	if open < 0 {
		return nil, fmt.Errorf("no definition list (CREATE TABLE ... AS is not used)")
	}
	depth, end := 0, -1
	var items [][]string
	start := open + 1
	for i := open; i < len(toks); i++ {
		switch toks[i] {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				end = i
			}
		case ",":
			if depth == 1 {
				items = append(items, toks[start:i])
				start = i + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("unbalanced parentheses")
	}
	items = append(items, toks[start:end])
	t := &table{name: name, options: join(toks[end+1:]), columns: map[string]column{}, constraints: map[string]bool{}}
	for _, it := range items {
		if len(it) == 0 {
			return nil, fmt.Errorf("an empty definition")
		}
		switch it[0] {
		case "constraint", "primary", "unique", "check", "foreign":
			t.constraints[join(it)] = true
			continue
		}
		key := strings.ToLower(unquote(it[0]))
		if _, dup := t.columns[key]; dup {
			return nil, fmt.Errorf("column %s twice", it[0])
		}
		ct := append([]string{key}, it[1:]...)
		t.columns[key] = column{name: unquote(it[0]), toks: ct, def: join(ct)}
		t.order = append(t.order, key)
	}
	return t, nil
}

// widened reports whether newer differs from older only in CHECK clauses
// of the form CHECK (x IN (...)) whose list only gains values.
func widened(older, newer []string) bool {
	ra, ca := checks(older)
	rb, cb := checks(newer)
	if join(ra) != join(rb) || len(ca) != len(cb) {
		return false
	}
	gained := false
	for i := range ca {
		if join(ca[i]) == join(cb[i]) {
			continue
		}
		xa, la, oka := inList(ca[i])
		xb, lb, okb := inList(cb[i])
		if !oka || !okb || xa != xb || len(lb) <= len(la) {
			return false
		}
		for _, v := range la {
			if !slices.Contains(lb, v) {
				return false
			}
		}
		gained = true
	}
	return gained
}

// checks takes a column definition's tokens apart into those outside its
// CHECK clauses and the clauses (each with its CONSTRAINT name).
func checks(toks []string) ([]string, [][]string) {
	var rest []string
	var out [][]string
	for i := 0; i < len(toks); i++ {
		j := i
		if toks[i] == "constraint" && i+2 < len(toks) && toks[i+2] == "check" {
			j = i + 2
		}
		if toks[j] != "check" || j+1 >= len(toks) || toks[j+1] != "(" {
			rest = append(rest, toks[i])
			continue
		}
		depth, k := 0, j+1
		for ; k < len(toks); k++ {
			if toks[k] == "(" {
				depth++
			} else if toks[k] == ")" {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if k == len(toks) {
			k--
		}
		out = append(out, toks[i:k+1])
		i = k
	}
	return rest, out
}

// inList reads [CONSTRAINT n] CHECK ( x IN ( v , v ... ) ).
func inList(clause []string) (string, []string, bool) {
	toks := clause
	if toks[0] == "constraint" {
		toks = toks[2:]
	}
	if len(toks) < 8 || toks[1] != "(" || toks[3] != "in" || toks[4] != "(" || toks[len(toks)-1] != ")" || toks[len(toks)-2] != ")" {
		return "", nil, false
	}
	var vals []string
	for i, v := range toks[5 : len(toks)-2] {
		if i%2 == 1 {
			if v != "," {
				return "", nil, false
			}
			continue
		}
		if v == "(" || v == ")" || v == "," {
			return "", nil, false
		}
		vals = append(vals, v)
	}
	return toks[2], vals, true
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
