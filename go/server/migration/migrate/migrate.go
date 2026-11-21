// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migrate is varlatchd's half of the migration from the TypeScript
// server (ADR-0059 Decision 9; internal docs/design/go-step7.md decisions 2
// to 5, 16 and 17, slice 7.3a):
//
//   - Import builds a fresh database from a forward bundle (bundle-v1): in
//     one write job, foreign keys deferred to the commit (the schema's
//     tables refer to each other in cycles), every copied table's rows
//     inserted as they are (ciphertexts byte for byte), the two
//     transformations applied, every foreign key checked and the Root KEK
//     checked against the installation's canary before anything commits;
//   - ExportReverse writes the reverse bundle from a snapshot copy of the
//     database, the transformations applied to the copy only.
//
// The two transformations (the manifest's "transformations"):
//
//   - browser-sessions-end: each source session is inserted and deleted
//     at once, so schema.sql's session_end_revokes_browser_credentials
//     trigger revokes its browser credentials and writes their
//     credential.revoked events exactly as a sign-out does; the session
//     row itself is never kept (its token is not carried);
//   - audit-append: after the source's events (the same positions) and
//     those revocations comes one installation.migrated event.
//
// Neither reads a plaintext: nothing here decrypts but the canary check.
package migrate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// MigratedEvent is the event the migration appends (audit-append).
const MigratedEvent = "installation.migrated"

// sessionTransformation is the manifest's transformation of the session
// table.
const sessionTransformation = "browser-sessions-end"

// Result is what an import or an export did.
type Result struct {
	InstallationID string         `json:"installationId"`
	Direction      string         `json:"direction"`
	Tables         int            `json:"tables"`
	Rows           int64          `json:"rows"`
	PerTable       map[string]int `json:"perTable"`
	// SessionsEnded and CredentialsRevoked are browser-sessions-end's.
	SessionsEnded      int   `json:"sessionsEnded"`
	CredentialsRevoked int   `json:"credentialsRevoked"`
	MigratedPosition   int64 `json:"migratedPosition"`
}

// Options are an import's or an export's.
type Options struct {
	// DataDir is the data directory: empty but for the names in Ignore, for
	// an import.
	DataDir string
	Ignore  []string
	// RootKEK checks the imported installation's canary.
	RootKEK []byte
	// Release is this varlatchd's, recorded in the schema and the events.
	Release string
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

func (o Options) now() func() time.Time {
	if o.Now == nil {
		return time.Now
	}
	return o.Now
}

// columns is a manifest table's columns in the target: their names, and
// the position of each in a source row (left-out columns are skipped).
type columns struct {
	names []string
	from  []int
}

func targetColumns(t manifest.Table) columns {
	var c columns
	for i, col := range t.Columns {
		if col.LeftOut != nil {
			continue
		}
		name := col.Target
		if name == "" {
			name = col.Source
		}
		c.names = append(c.names, name)
		c.from = append(c.from, i)
	}
	return c
}

func targetTable(t manifest.Table) string {
	if t.Target != "" {
		return t.Target
	}
	return t.Source
}

// ident quotes an SQLite identifier.
func ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func insertSQL(table string, names []string) string {
	q := make([]string, len(names))
	quoted := make([]string, len(names))
	for i, n := range names {
		q[i], quoted[i] = "?", ident(n)
	}
	return "INSERT INTO " + ident(table) + " (" + strings.Join(quoted, ", ") + ") VALUES (" + strings.Join(q, ", ") + ")"
}

// staleTemp is what an import or a reverse export that was killed leaves
// in the data directory: the database under its temporary name
// (.migrate-import-<12 hex>.db, .migrate-export-<12 hex>.db), and that
// name's WAL and shared memory.
var staleTemp = regexp.MustCompile(`^\.migrate-(import|export)-[0-9a-f]{12}\.db(-wal|-shm)?$`)

// fresh checks dir holds nothing but the ignored names, after removing what
// an import or a reverse export that was killed left (that exact pattern
// only, regular files only: the caller holds the data directory, with no
// varlatchd running, so neither runs now). Anything else, a look-alike
// included, is refused and named.
func fresh(dir string, ignore []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if slices.Contains(ignore, e.Name()) {
			continue
		}
		if staleTemp.MatchString(e.Name()) && e.Type().IsRegular() {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("an interrupted import or export left %s, which cannot be removed: %w", e.Name(), err)
			}
			continue
		}
		return fmt.Errorf("the data directory %s is not empty (%s): an import builds a fresh database only", dir, e.Name())
	}
	return nil
}

// importPrefix names the database an import builds before it is renamed
// into place: a dotted temporary name in the data directory, which a
// later import removes when an interrupted one left it (fresh).
const importPrefix = ".migrate-import-"

// Import builds a fresh database in o.DataDir from the forward bundle in.
// The bundle is read twice: first whole, its counts and SHA-256 checked
// (bundle.Verify), so a stream cut short or damaged is refused as such
// before anything is written; then into a database under a temporary
// name, which is renamed to varlatch.db only once its one write job
// committed and its file is synced. On an error nothing is kept, and an
// import that was killed leaves only the temporary name, which the next
// import removes.
func Import(ctx context.Context, in io.ReadSeeker, o Options) (res Result, err error) {
	m, err := manifest.Load()
	if err != nil {
		return res, err
	}
	if err := fresh(o.DataDir, o.Ignore); err != nil {
		return res, err
	}
	if _, err := bundle.Verify(in, m); err != nil {
		return res, err
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return res, err
	}
	r, err := bundle.NewReader(in, m)
	if err != nil {
		return res, err
	}
	h := r.Header()
	if h.Direction != bundle.Forward {
		return res, errors.New("migrate: an import reads a forward bundle (the TypeScript server's export); this one is a reverse bundle")
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return res, err
	}
	temp := filepath.Join(o.DataDir, importPrefix+hex.EncodeToString(suffix)+".db")
	removeTemp := func() {
		for _, s := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(temp + s)
		}
	}
	defer func() {
		if err != nil {
			removeTemp()
		}
	}()
	store, err := storage.Open(ctx, storage.Options{Path: temp, DeferForeignKeys: true})
	if err != nil {
		return res, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = store.Close()
		}
	}()
	if _, err := db.Init(ctx, store, o.Release); err != nil {
		return res, err
	}
	res = Result{Direction: bundle.Forward, PerTable: map[string]int{}}
	actx := audit.WithClock(ctx, o.now())
	err = store.Write(actx, func(tx *storage.Tx) error {
		if _, err := tx.ExecContext(actx, "PRAGMA defer_foreign_keys = ON"); err != nil {
			return err
		}
		for range bundle.Tables(m) {
			t, n, err := r.NextTable()
			if err != nil {
				return err
			}
			res.Tables++
			res.PerTable[t.Source] = n
			if err := importTable(actx, tx, r, t, n, &res); err != nil {
				return fmt.Errorf("migrate: table %s: %w", t.Source, err)
			}
		}
		if err := r.End(); err != nil {
			return err
		}
		recorded, err := audit.Record(actx, tx, audit.Event{
			Type: MigratedEvent, Decision: audit.Info,
			Metadata: migratedMetadata(m, h, res),
		})
		if err != nil {
			return err
		}
		res.MigratedPosition = recorded[0].Position
		if err := foreignKeysHold(actx, tx); err != nil {
			return err
		}
		if err := noSequences(actx, tx); err != nil {
			return err
		}
		id, err := canaryHolds(actx, tx, o.RootKEK)
		res.InstallationID = id
		return err
	})
	if err != nil {
		return res, err
	}
	// Closed, the WAL checkpointed into the file (TRUNCATE): the file is
	// the whole database, synced, then renamed into place.
	closed = true
	if err := store.Close(); err != nil {
		return res, err
	}
	if st, err := os.Stat(temp + "-wal"); err == nil && st.Size() > 0 {
		return res, errors.New("migrate: the imported database's WAL was not checkpointed into it on close")
	}
	if err := syncFile(temp); err != nil {
		return res, err
	}
	final := filepath.Join(o.DataDir, config.DatabaseFile)
	if err := os.Rename(temp, final); err != nil {
		return res, err
	}
	for _, s := range []string{"-wal", "-shm"} {
		_ = os.Remove(temp + s)
	}
	if err := syncFile(o.DataDir); err != nil {
		_ = os.Remove(final)
		return res, err
	}
	return res, nil
}

// syncFile makes a file, or a directory's entries, durable.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// importTable inserts one table's rows, or applies its transformation.
func importTable(ctx context.Context, tx *storage.Tx, r *bundle.Reader, t manifest.Table, n int, res *Result) error {
	cols := targetColumns(t)
	switch {
	case t.Action == manifest.Transform && t.Transformation == sessionTransformation:
		return endSessions(ctx, tx, r, t, n, res)
	case t.Action != manifest.Copy:
		return fmt.Errorf("a %s table with transformation %q this import does not apply", t.Action, t.Transformation)
	}
	if t.ReplacesSeedRow {
		// The source's one row replaces the row a new database seeds.
		if n != 1 {
			return fmt.Errorf("%d rows where the source's one row replaces the seeded one", n)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+ident(targetTable(t))); err != nil {
			return err
		}
	}
	stmt := insertSQL(targetTable(t), cols.names)
	args := make([]any, len(cols.from))
	for i := 0; i < n; i++ {
		row, err := r.Row()
		if err != nil {
			return err
		}
		values, err := bundle.Decode(t, row)
		if err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
		for j, k := range cols.from {
			args[j] = values[k]
		}
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
		res.Rows++
	}
	return nil
}

// endSessions is browser-sessions-end: each session inserted, then deleted,
// so the trigger ends it as a sign-out does. Its token is not carried; the
// row holds, for the moment it exists, a hash no token has.
func endSessions(ctx context.Context, tx *storage.Tx, r *bundle.Reader, t manifest.Table, n int, res *Result) error {
	cols := targetColumns(t)
	tokenAt := -1
	for i, c := range t.Columns {
		if c.LeftOut != nil && c.Target == "token_hash" {
			tokenAt = i
		}
	}
	if tokenAt < 0 {
		return errors.New("the manifest's session table has no left-out token")
	}
	names := append(slices.Clone(cols.names), "token_hash")
	stmt := insertSQL(targetTable(t), names)
	idAt := slices.Index(cols.names, "id")
	if idAt < 0 {
		return errors.New("the manifest's session table has no id")
	}
	args := make([]any, len(names))
	for i := 0; i < n; i++ {
		row, err := r.Row()
		if err != nil {
			return err
		}
		values, err := bundle.Decode(t, row)
		if err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
		for j, k := range cols.from {
			args[j] = values[k]
		}
		id, _ := args[idAt].(string)
		if id == "" {
			return fmt.Errorf("row %d: a session without an id", i+1)
		}
		sum := sha256.Sum256([]byte("varlatch migration: a session ended, never signed in with: " + id))
		args[len(names)-1] = hex.EncodeToString(sum[:])
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
		revoked, err := revokedBy(ctx, tx, func() error {
			_, err := tx.ExecContext(ctx, "DELETE FROM auth_sessions WHERE id = ?", id)
			return err
		})
		if err != nil {
			return fmt.Errorf("row %d: ending the session: %w", i+1, err)
		}
		res.SessionsEnded++
		res.CredentialsRevoked += revoked
	}
	return nil
}

// revokedBy runs end, which deletes sessions, and counts the
// credential.revoked events the trigger wrote for it: what it revoked,
// never a guess at the trigger's predicate (an expired credential is left
// as it is, and counted nowhere).
func revokedBy(ctx context.Context, tx *storage.Tx, end func() error) (int, error) {
	var before int64
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(event_order), 0) FROM audit_events").Scan(&before); err != nil {
		return 0, err
	}
	if err := end(); err != nil {
		return 0, err
	}
	var n int
	err := tx.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE event_order > ? AND event_type = 'credential.revoked'", before).Scan(&n)
	return n, err
}

func migratedMetadata(m *manifest.Manifest, h bundle.Header, res Result) jsvalue.Object {
	frozen := jsvalue.Object{{Key: "auditPosition", Value: h.FrozenPoint.AuditPosition}}
	if h.FrozenPoint.Snapshot != "" {
		frozen = append(frozen, jsvalue.Member{Key: "snapshot", Value: h.FrozenPoint.Snapshot})
	}
	return jsvalue.Object{
		{Key: "direction", Value: h.Direction},
		{Key: "sourceRelease", Value: h.Release},
		{Key: "manifestVersion", Value: m.Version},
		{Key: "frozenPoint", Value: frozen},
		{Key: "sessionsEnded", Value: res.SessionsEnded},
		{Key: "credentialsRevoked", Value: res.CredentialsRevoked},
	}
}

// foreignKeysHold checks every foreign key before the commit, naming the
// first rows that break one.
func foreignKeysHold(ctx context.Context, tx *storage.Tx) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var broken []string
	for rows.Next() {
		var table, parent string
		var rowid any
		var fk int
		if err := rows.Scan(&table, &rowid, &parent, &fk); err != nil {
			return err
		}
		if len(broken) < 10 {
			broken = append(broken, fmt.Sprintf("%s row %v refers to a missing %s", table, rowid, parent))
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(broken) > 0 {
		return fmt.Errorf("migrate: foreign keys do not hold: %s", strings.Join(broken, "; "))
	}
	return nil
}

// noSequences asserts the database has no sequence (decision 16): every id
// is made by the application, and SQLite keeps one only for an
// AUTOINCREMENT table.
func noSequences(ctx context.Context, tx *storage.Tx) error {
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name = 'sqlite_sequence'").Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return errors.New("migrate: the database has a sequence (sqlite_sequence); the migration carries none")
	}
	return nil
}

// canaryHolds checks the Root KEK opens the installation's canary.
func canaryHolds(ctx context.Context, tx *storage.Tx, rootKEK []byte) (string, error) {
	row, err := query.New(tx).GetInstallation(ctx)
	if err != nil {
		return "", fmt.Errorf("migrate: the bundle holds no installation: %w", err)
	}
	var canary envelope.Envelope
	if err := json.Unmarshal([]byte(row.KekCanary), &canary); err != nil || !envelope.VerifyCanary(rootKEK, canary, row.ID) {
		return row.ID, errors.New("migrate: the Root KEK does not open the installation's canary: an import needs the installation's own Root KEK")
	}
	return row.ID, nil
}
