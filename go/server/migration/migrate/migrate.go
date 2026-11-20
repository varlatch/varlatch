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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	"github.com/varlatch/varlatch/go/server/migration/canonical"
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
		if col.LeftOut != "" {
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

// fresh checks dir holds nothing but the ignored names.
func fresh(dir string, ignore []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !slices.Contains(ignore, e.Name()) {
			return fmt.Errorf("the data directory %s is not empty (%s): an import builds a fresh database only", dir, e.Name())
		}
	}
	return nil
}

// Import builds a fresh database in o.DataDir from the forward bundle in.
// The bundle is read twice: first whole, its counts and SHA-256 checked
// (bundle.Verify), so a stream cut short or damaged is refused as such
// before anything is written; then into the database. On any error nothing
// is kept: the database files it made are removed.
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
	path := filepath.Join(o.DataDir, config.DatabaseFile)
	store, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		return res, err
	}
	defer func() {
		if cerr := store.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				_ = os.Remove(path + suffix)
			}
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
	return res, err
}

// importTable inserts one table's rows, or applies its transformation.
func importTable(ctx context.Context, tx *storage.Tx, r *bundle.Reader, t manifest.Table, n int, res *Result) error {
	types := t.Types()
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
		values, err := canonical.DecodeRow(types, row)
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
	types := t.Types()
	cols := targetColumns(t)
	tokenAt := -1
	for i, c := range t.Columns {
		if c.LeftOut != "" && c.Target == "token_hash" {
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
		values, err := canonical.DecodeRow(types, row)
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
		var live int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM credentials WHERE auth_session_id = ? AND kind = 'browser' AND revoked_at IS NULL", id).Scan(&live); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM auth_sessions WHERE id = ?", id); err != nil {
			return fmt.Errorf("row %d: ending the session: %w", i+1, err)
		}
		res.SessionsEnded++
		res.CredentialsRevoked += live
	}
	return nil
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
