// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// tables is pass 2 over the tables: the rows check of each, and the
// authentication check of the tables it reads; then the tables the
// bundle does not carry.
func (c *checker) tables(ctx context.Context, r *bundle.Reader) error {
	for range bundle.Tables(c.m) {
		t, n, err := r.NextTable()
		if err != nil {
			return err
		}
		if err := c.table(ctx, r, t, n); err != nil {
			return fmt.Errorf("check: table %s: %w", t.Source, err)
		}
	}
	if err := c.otherTables(ctx); err != nil {
		return err
	}
	return c.authenticationEnd(ctx)
}

// table compares one table's rows with the target's, in the manifest's
// order: canonical bytes against canonical bytes, rows matched by their
// key (the manifest's orderBy), or by position where the manifest keeps
// the source's physical order. The audit log is compared up to the frozen
// point (the audit check reads what follows); a credential the migration
// revoked is expected with the revocation the audit check found.
func (c *checker) table(ctx context.Context, r *bundle.Reader, t manifest.Table, n int) error {
	c.checked(Rows, int64(n))
	if t.Action == manifest.Transform {
		// browser-sessions-end: no session is kept.
		var left int
		if err := c.db.QueryRowContext(ctx, "SELECT count(*) FROM "+ident(targetTable(t))).Scan(&left); err != nil {
			return err
		}
		if left != 0 {
			c.fail(Rows, t.Source, "", "%d rows in %s; every session ends in the migration", left, targetTable(t))
		}
		for range n {
			if _, err := r.Row(); err != nil {
				return err
			}
		}
		return nil
	}
	sel := make([]string, len(t.Columns))
	for i, col := range t.Columns {
		if col.LeftOut != nil {
			sel[i] = "NULL"
		} else {
			sel[i] = ident(targetColumn(col))
		}
	}
	q := "SELECT " + strings.Join(sel, ", ") + " FROM " + ident(targetTable(t))
	if t.Source == "audit_events" {
		q += " WHERE " + ident("event_order") + " <= ?"
	}
	if t.PhysicalOrder {
		q += " ORDER BY rowid"
	} else {
		order := make([]string, len(t.OrderBy))
		for i, k := range t.OrderBy {
			order[i] = ident(targetColumn(t.Columns[column(t, k)])) + " COLLATE BINARY"
		}
		q += " ORDER BY " + strings.Join(order, ", ")
	}
	var args []any
	if t.Source == "audit_events" {
		args = append(args, c.head.FrozenPoint.AuditPosition)
	}
	rows, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	types := t.Types()
	target := func() ([]any, bool, error) {
		if !rows.Next() {
			return nil, false, rows.Err()
		}
		vals := make([]any, len(types))
		ptrs := make([]any, len(types))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, false, err
		}
		c.expectTransformed(t, vals)
		return vals, true, nil
	}
	source := func() ([]byte, []any, error) {
		b, err := r.Row()
		if err != nil {
			return nil, nil, err
		}
		v, err := bundle.Decode(t, b)
		if err != nil {
			return nil, nil, err
		}
		if err := c.authenticationRow(ctx, t, v); err != nil {
			return nil, nil, err
		}
		return b, v, nil
	}
	if t.PhysicalOrder {
		return c.physical(t, n, types, target, source)
	}
	tv, more, err := target()
	if err != nil {
		return err
	}
	var prev []any
	for i := 1; i <= n; i++ {
		b, sv, err := source()
		if err != nil {
			return err
		}
		// The merge below needs the bundle in the manifest's order, each
		// key once, as BUNDLE.md has the writer write it.
		if prev != nil && compareKeys(t, prev, sv) >= 0 {
			c.fail(Rows, t.Source, "", "the bundle's row %d is out of the manifest's order", i)
		}
		prev = sv
		// The target's rows before this one by key are extra.
		for more && compareKeys(t, tv, sv) < 0 {
			c.fail(Rows, t.Source, "", "a row the source does not have, before the source's row %d", i)
			if tv, more, err = target(); err != nil {
				return err
			}
		}
		if !more || compareKeys(t, tv, sv) > 0 {
			c.fail(Rows, t.Source, "", "the source's row %d is missing", i)
			continue
		}
		got, err := canonical.AppendRow(nil, types, tv)
		if err != nil {
			c.fail(Rows, t.Source, "", "row %d cannot be written as a canonical row (%s)", i, badColumn(t, err))
		} else if !bytes.Equal(got, b) {
			c.fail(Rows, t.Source, "", "row %d differs from the source's in %s", i, strings.Join(differing(t, tv, sv), ", "))
		}
		if tv, more, err = target(); err != nil {
			return err
		}
	}
	for more {
		c.fail(Rows, t.Source, "", "a row the source does not have, after the source's last row")
		if tv, more, err = target(); err != nil {
			return err
		}
	}
	return nil
}

// physical compares a table the manifest keeps in the source's physical
// order (its rowid order in the target), position by position. When the
// target holds the source's rows but in another order, that is the fault
// named, once.
func (c *checker) physical(t manifest.Table, n int, types []canonical.Type, target func() ([]any, bool, error), source func() ([]byte, []any, error)) error {
	var want, got [][]byte
	for range n {
		b, _, err := source()
		if err != nil {
			return err
		}
		want = append(want, b)
	}
	for k := 1; ; k++ {
		tv, more, err := target()
		if err != nil {
			return err
		}
		if !more {
			break
		}
		b, err := canonical.AppendRow(nil, types, tv)
		if err != nil {
			c.fail(Rows, t.Source, "", "row %d cannot be written as a canonical row (%s)", k, badColumn(t, err))
			b = nil
		}
		got = append(got, b)
	}
	same := len(want) == len(got)
	first := -1
	for i := range min(len(want), len(got)) {
		if !bytes.Equal(want[i], got[i]) {
			same = false
			if first < 0 {
				first = i
			}
		}
	}
	if same {
		return nil
	}
	sorted := func(rows [][]byte) [][]byte {
		out := slices.Clone(rows)
		slices.SortFunc(out, bytes.Compare)
		return out
	}
	if len(want) == len(got) && slices.EqualFunc(sorted(want), sorted(got), bytes.Equal) {
		c.fail(Rows, t.Source, "", "the target holds the source's rows out of the source's physical order, from row %d", first+1)
		return nil
	}
	for i := range max(len(want), len(got)) {
		switch {
		case i >= len(got):
			c.fail(Rows, t.Source, "", "the source's row %d is missing", i+1)
		case i >= len(want):
			c.fail(Rows, t.Source, "", "a row the source does not have, after the source's last row")
		case !bytes.Equal(want[i], got[i]):
			c.fail(Rows, t.Source, "", "row %d differs from the source's", i+1)
		}
	}
	return nil
}

// expectTransformed undoes, in a target row, what the transformations
// changed by design, once the audit check has found it: a credential the
// migration revoked shows the source's null revoked_at when its
// revoked_at is its revocation event's moment. Equal, not merely close:
// session_end_revokes_browser_credentials writes the event (occurred_at's
// default) and the revocation (its UPDATE) with unixepoch('subsec') in one
// trigger run of the one DELETE, and SQLite fixes the time once per
// statement (sqlite3_step), so both read the same instant. A schema change
// that wrote either outside that statement would fail this check, by
// design, until the expectation is changed with it.
func (c *checker) expectTransformed(t manifest.Table, vals []any) {
	if t.Source != "credentials" {
		return
	}
	id, _ := vals[column(t, "id")].(string)
	at, ok := c.revoked[id]
	if !ok {
		return
	}
	rc := column(t, "revoked_at")
	if got, isInt := vals[rc].(int64); isInt && got == at {
		vals[rc] = nil
	}
}

// differing names the columns where a target row and a source row differ.
func differing(t manifest.Table, tv, sv []any) []string {
	var out []string
	for i, col := range t.Columns {
		a, errA := canonical.AppendValue(nil, col.Type, tv[i])
		b, errB := canonical.AppendValue(nil, col.Type, sv[i])
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			out = append(out, col.Source)
		}
	}
	if len(out) == 0 {
		out = []string{"its form"}
	}
	return out
}

// badColumn names the column an encoder's error is about, never the error
// itself: it can quote the value.
func badColumn(t manifest.Table, err error) string {
	var n int
	if _, scanErr := fmt.Sscanf(err.Error(), "column %d:", &n); scanErr == nil && n >= 1 && n <= len(t.Columns) {
		return t.Columns[n-1].Source
	}
	return "a column"
}

// compareKeys orders two rows by the manifest's orderBy as SQLite does:
// NULL first, numbers by value, text and bytes by their bytes.
func compareKeys(t manifest.Table, a, b []any) int {
	for _, k := range t.OrderBy {
		i := column(t, k)
		if c := compareValues(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

func compareValues(a, b any) int {
	a, b = normalize(a), normalize(b)
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	switch x := a.(type) {
	case int64:
		if y, ok := b.(int64); ok {
			return cmp.Compare(x, y)
		}
		return -1 // a number before text or bytes, as SQLite orders them
	case string:
		switch y := b.(type) {
		case string:
			return strings.Compare(x, y)
		case int64:
			return 1
		}
		return -1
	case []byte:
		if y, ok := b.([]byte); ok {
			return bytes.Compare(x, y)
		}
		return 1
	}
	return 0
}

// normalize is a value as SQLite holds it: a boolean as 0 or 1.
func normalize(v any) any {
	if b, ok := v.(bool); ok {
		if b {
			return int64(1)
		}
		return int64(0)
	}
	return v
}

// reverseKeeps are the target-only tables a reverse's target (Go's copy,
// after it served) may hold rows in: varlatchd's own records, which no
// bundle carries. certificate_issuances is the public name's issuance
// count (schema version 2), carried across a reverse apart from the bundle
// (migrate's migration-issuances.json). exercise_credentials and
// oidc_token_uses (schema version 4) stay behind: what they limit is inert
// on the TypeScript server (ADR-0060). So does one_time_codes_given (schema
// version 5): the seeds are no values there (ADR-0061). So do
// oauth_connections and oauth_authorizations (schema version 6): nothing is
// refreshed there (ADR-0062). And entry_links (schema version 7): there is
// no page to enter a value on (ADR-0063).
var reverseKeeps = map[string]bool{"certificate_issuances": true, "exercise_credentials": true, "oidc_token_uses": true, "one_time_codes_given": true,
	"oauth_connections": true, "oauth_authorizations": true, "entry_links": true}

// otherTables checks the target holds no table the bundle does not
// account for, and the target-only tables what an import writes:
// schema_version its one row, any other none. In the reverse checks the
// target is Go's copy, not an import: a table of reverseKeeps may hold
// rows there; every other target-only table is held as an import's.
func (c *checker) otherTables(ctx context.Context) error {
	known := map[string]bool{}
	for _, t := range bundle.Tables(c.m) {
		known[targetTable(t)] = true
	}
	rows, err := c.db.QueryContext(ctx, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	if err := closeRows(rows); err != nil {
		return err
	}
	for _, name := range names {
		if known[name] {
			continue
		}
		if _, targetOnly := c.m.TargetOnly.Tables[name]; !targetOnly {
			c.fail(Rows, name, "", "a table neither the bundle nor the manifest's target-only tables account for")
			continue
		}
		if c.o.Reverse && reverseKeeps[name] {
			continue
		}
		var n int
		if err := c.db.QueryRowContext(ctx, "SELECT count(*) FROM "+ident(name)).Scan(&n); err != nil {
			return err
		}
		want := 0
		if name == "schema_version" {
			want = 1
		}
		if n != want {
			c.fail(Rows, name, "", "%d rows in a target-only table; an import writes %d", n, want)
		}
	}
	return nil
}

// scanAll reads every row of a query.
func scanAll(rows *sql.Rows, n int) ([][]any, error) {
	var out [][]any
	for rows.Next() {
		vals := make([]any, n)
		ptrs := make([]any, n)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, vals)
	}
	return out, closeRows(rows)
}
