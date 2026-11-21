// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// migratedEvent is the event the import appends (transformation
// audit-append).
const migratedEvent = "installation.migrated"

// cursorColumns are the audit cursors: each table's key columns are its
// manifest orderBy, its cursor columns these (source names).
var cursorColumns = map[string][]string{
	"webhooks":          {"cursor_order", "cursor_occurred_at", "cursor_event_id"},
	"audit_exports":     {"cursor_order"},
	"sync_cursor":       {"cursor_order", "occurred_at", "event_id"},
	"exposure_backfill": {"cursor", "until_order"},
}

// sourceEvent is one source audit event: its id at its position.
type sourceEvent struct {
	id    string
	order int64
}

// firstPass reads the bundle for what the checks need before the rows: the
// sessions, the live browser credentials minted from one, the cursors, the
// audit log's ids by position, and the counts.
func (c *checker) firstPass(in io.Reader) error {
	r, err := bundle.NewReader(in, c.m)
	if err != nil {
		return err
	}
	c.head = r.Header()
	c.sessions = map[string]bool{}
	c.browser = map[string]browserCredential{}
	c.cursors = map[string]map[string][]any{}
	for range bundle.Tables(c.m) {
		t, n, err := r.NextTable()
		if err != nil {
			return err
		}
		c.counts.Tables++
		c.counts.Rows += int64(n)
		for range n {
			row, err := r.Row()
			if err != nil {
				return err
			}
			if !firstPassTable(t.Source) {
				continue
			}
			v, err := bundle.Decode(t, row)
			if err != nil {
				return fmt.Errorf("check: table %s: %w", t.Source, err)
			}
			c.firstPassRow(t, v)
		}
	}
	if n, err := r.Digests(); err != nil {
		return err
	} else {
		c.counts.Digests = n
		for range n {
			if _, err := r.Digest(); err != nil {
				return err
			}
		}
	}
	n, _, err := r.Decisions()
	if err != nil {
		return err
	}
	c.counts.Decisions = n
	for range n {
		if _, err := r.Decision(); err != nil {
			return err
		}
	}
	return r.End()
}

func firstPassTable(source string) bool {
	_, cursor := cursorColumns[source]
	return cursor || source == "session" || source == "credentials" || source == "audit_events"
}

func (c *checker) firstPassRow(t manifest.Table, v []any) {
	str := func(col string) string {
		s, _ := v[column(t, col)].(string)
		return s
	}
	switch t.Source {
	case "session":
		c.sessions[str("id")] = true
	case "credentials":
		if str("kind") == "browser" && str("auth_session_id") != "" && v[column(t, "revoked_at")] == nil {
			bc := browserCredential{session: str("auth_session_id")}
			if e, ok := v[column(t, "expires_at")].(int64); ok {
				bc.expires = &e
			}
			c.browser[str("id")] = bc
		}
	case "audit_events":
		order, _ := v[column(t, "event_order")].(int64)
		c.sourceEvents = append(c.sourceEvents, sourceEvent{id: str("id"), order: order})
	}
	if cols, ok := cursorColumns[t.Source]; ok {
		vals := make([]any, len(cols))
		for i, col := range cols {
			vals[i] = v[column(t, col)]
		}
		if c.cursors[t.Source] == nil {
			c.cursors[t.Source] = map[string][]any{}
		}
		c.cursors[t.Source][keyText(t, v)] = vals
	}
}

// keyText is a row's key (its manifest orderBy values) as text, for maps.
func keyText(t manifest.Table, v []any) string {
	var b []byte
	for _, k := range t.OrderBy {
		col := column(t, k)
		var err error
		b, err = canonical.AppendValue(b, t.Columns[col].Type, v[col])
		if err != nil {
			b = append(b, '?')
		}
		b = append(b, 0)
	}
	return string(b)
}

// audit is the audit check: the source's log is the target's prefix, the
// same events at the same positions; after it only the revocations
// browser-sessions-end writes, each of a credential the migration ends,
// then one installation.migrated carrying the bundle's header; and every
// cursor where the source left it.
func (c *checker) audit(ctx context.Context) error {
	pos := c.head.FrozenPoint.AuditPosition
	last := int64(0)
	if len(c.sourceEvents) > 0 {
		last = c.sourceEvents[len(c.sourceEvents)-1].order
	}
	if last != pos {
		c.fail(Audit, "audit_events", "", "the bundle's last audit position is %d; its frozen point is %d", last, pos)
	}
	// The prefix, by position.
	rows, err := c.db.QueryContext(ctx, "SELECT id, event_order FROM audit_events WHERE event_order <= ? ORDER BY event_order", pos)
	if err != nil {
		return err
	}
	i := 0
	for rows.Next() {
		var e sourceEvent
		if err := rows.Scan(&e.id, &e.order); err != nil {
			rows.Close()
			return err
		}
		switch {
		case i >= len(c.sourceEvents):
			c.fail(Audit, "audit_events", "", "position %d holds %s, which the source does not have", e.order, e.id)
		case c.sourceEvents[i] != e:
			s := c.sourceEvents[i]
			c.fail(Audit, "audit_events", "", "position %d holds %s; the source's event %d is %s at position %d", e.order, e.id, i+1, s.id, s.order)
		}
		i++
	}
	if err := closeRows(rows); err != nil {
		return err
	}
	if i < len(c.sourceEvents) {
		c.fail(Audit, "audit_events", "", "the target's log holds %d events up to position %d; the source's %d", i, pos, len(c.sourceEvents))
	}
	c.checked(Audit, int64(len(c.sourceEvents)))

	// The tail: the revocations, then installation.migrated, last.
	rows, err = c.db.QueryContext(ctx, `SELECT id, event_order, event_type, credential_id, occurred_at, metadata
		FROM audit_events WHERE event_order > ? ORDER BY event_order`, pos)
	if err != nil {
		return err
	}
	type tailEvent struct {
		id, typ    string
		order, at  int64
		credential sql.NullString
		metadata   sql.NullString
	}
	var tail []tailEvent
	for rows.Next() {
		var e tailEvent
		if err := rows.Scan(&e.id, &e.order, &e.typ, &e.credential, &e.at, &e.metadata); err != nil {
			rows.Close()
			return err
		}
		tail = append(tail, e)
	}
	if err := closeRows(rows); err != nil {
		return err
	}
	c.checked(Audit, int64(len(tail)))
	c.revoked = map[string]int64{}
	if len(tail) == 0 || tail[len(tail)-1].typ != migratedEvent {
		c.fail(Audit, "audit_events", "", "the log does not end in one %s event", migratedEvent)
	}
	for k, e := range tail {
		if k == len(tail)-1 && e.typ == migratedEvent {
			c.migratedAt = e.at
			c.migratedMetadata(e.metadata)
			continue
		}
		if e.typ != "credential.revoked" || !e.credential.Valid {
			c.fail(Audit, "audit_events", "", "position %d after the frozen point holds %s (%s); only the migration's revocations and %s may follow it", e.order, e.id, e.typ, migratedEvent)
			continue
		}
		cred := e.credential.String
		if _, twice := c.revoked[cred]; twice {
			c.fail(Audit, "audit_events", "", "position %d revokes %s a second time", e.order, cred)
			continue
		}
		c.revoked[cred] = e.at
		if !c.ends(cred, e.at) {
			c.fail(Audit, "audit_events", "", "position %d revokes %s, which ending the source's sessions does not revoke", e.order, cred)
		}
		if reason, ok := metadataString(e.metadata, "reason"); !ok || reason != "session-ended" {
			c.fail(Audit, "audit_events", "", "position %d revokes %s for another reason than session-ended", e.order, cred)
		}
	}
	return c.cursorCheck(ctx)
}

// ends reports whether ending the source's sessions at the moment at
// revokes credential id: a live browser credential minted from one of
// them, unexpired at that moment (the trigger's predicate).
func (c *checker) ends(id string, at int64) bool {
	bc, ok := c.browser[id]
	return ok && c.sessions[bc.session] && (bc.expires == nil || *bc.expires > at)
}

func metadataString(meta sql.NullString, key string) (string, bool) {
	if !meta.Valid {
		return "", false
	}
	v, err := jsvalue.Parse([]byte(meta.String))
	if err != nil {
		return "", false
	}
	o, ok := v.(jsvalue.Object)
	if !ok {
		return "", false
	}
	s, ok := o.Get(key)
	if !ok {
		return "", false
	}
	str, ok := s.(string)
	return str, ok
}

// migratedMetadata checks installation.migrated carries the bundle's
// header and the transformation's counts.
func (c *checker) migratedMetadata(meta sql.NullString) {
	frozen := jsvalue.Object{{Key: "auditPosition", Value: c.head.FrozenPoint.AuditPosition}}
	if c.head.FrozenPoint.Snapshot != "" {
		frozen = append(frozen, jsvalue.Member{Key: "snapshot", Value: c.head.FrozenPoint.Snapshot})
	}
	want, _ := jsvalue.Canonical(jsvalue.Stringify(jsvalue.Object{
		{Key: "direction", Value: c.head.Direction},
		{Key: "sourceRelease", Value: c.head.Release},
		{Key: "manifestVersion", Value: c.m.Version},
		{Key: "frozenPoint", Value: frozen},
		{Key: "sessionsEnded", Value: len(c.sessions)},
		{Key: "credentialsRevoked", Value: len(c.revoked)},
	}))
	got := ""
	if meta.Valid {
		got, _ = jsvalue.Canonical([]byte(meta.String))
	}
	if got != want {
		c.fail(Audit, "audit_events", "", "%s does not carry the bundle's direction, release, manifest version and frozen point, and %d sessions ended, %d credentials revoked",
			migratedEvent, len(c.sessions), len(c.revoked))
	}
}

// cursorCheck compares each audit cursor, read on its own by its row's
// key, with the source's.
func (c *checker) cursorCheck(ctx context.Context) error {
	tables := make([]string, 0, len(cursorColumns))
	for t := range cursorColumns {
		tables = append(tables, t)
	}
	slices.Sort(tables)
	for _, source := range tables {
		t, ok := c.m.Table(source)
		if !ok {
			return fmt.Errorf("check: the manifest has no table %s", source)
		}
		cols := cursorColumns[source]
		sel := make([]string, 0, len(t.OrderBy)+len(cols))
		types := make([]canonical.Type, 0, len(t.OrderBy)+len(cols))
		for _, k := range append(slices.Clone(t.OrderBy), cols...) {
			col := t.Columns[column(t, k)]
			sel = append(sel, ident(targetColumn(col)))
			types = append(types, col.Type)
		}
		rows, err := c.db.QueryContext(ctx, "SELECT "+strings.Join(sel, ", ")+" FROM "+ident(targetTable(t)))
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for rows.Next() {
			vals := make([]any, len(sel))
			ptrs := make([]any, len(sel))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return err
			}
			// The key as the source's row would give it.
			keyRow := make([]any, len(t.Columns))
			for i, k := range t.OrderBy {
				keyRow[column(t, k)] = vals[i]
			}
			key := keyText(t, keyRow)
			seen[key] = true
			want, ok := c.cursors[source][key]
			name := keyName(t, keyRow)
			if !ok {
				c.fail(Audit, source, "", "%s: a cursor the source does not have", name)
				continue
			}
			for i, col := range cols {
				a, errA := canonical.AppendValue(nil, types[len(t.OrderBy)+i], vals[len(t.OrderBy)+i])
				b, errB := canonical.AppendValue(nil, types[len(t.OrderBy)+i], want[i])
				if errA != nil || errB != nil || string(a) != string(b) {
					c.fail(Audit, source, "", "%s: the cursor moved (%s)", name, col)
				}
			}
			c.checked(Audit, 1)
		}
		if err := closeRows(rows); err != nil {
			return err
		}
		for key := range c.cursors[source] {
			if !seen[key] {
				c.fail(Audit, source, "", "a cursor of the source is missing")
			}
		}
	}
	return nil
}

// keyName names a row by its key for the report: its id where the key is
// an id column; otherwise only the key's columns, since a key can be a
// hash of a secret (a state hash, a device code's).
func keyName(t manifest.Table, v []any) string {
	if len(t.OrderBy) == 1 {
		if s, ok := v[column(t, t.OrderBy[0])].(string); ok && idLike(t.OrderBy[0]) {
			return s
		}
	}
	return "the row (" + strings.Join(t.OrderBy, ", ") + ")"
}

// idLike is a key column holding an id, which the report may name (never
// a hash, a token or a value).
func idLike(col string) bool { return col == "id" || col == "passkey_id" || col == "session_id" }

func closeRows(rows *sql.Rows) error {
	err := rows.Err()
	if cerr := rows.Close(); err == nil {
		err = cerr
	}
	return err
}
