// SPDX-License-Identifier: AGPL-3.0-or-later

// Package db is varlatchd's SQLite schema (ADR-0059 Decision 2) and its
// version: schema.sql, the queries sqlc generates from it (package query),
// and Init, which prepares the database at first start.
//
// MAPPING.md and mapping.json record how every PostgreSQL table, column,
// constraint, index and trigger of the TypeScript server at v0.22.0 maps to
// schema.sql, or why it was dropped; the migration manifest (Decision 9) is
// built from them.
package db

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

//go:embed schema.sql
var schemaSQL string

// Schema returns schema.sql, the statements that create the schema of
// version SchemaVersion on an empty database.
func Schema() string { return schemaSQL }

// SchemaVersion is the version of schema.sql, recorded in the database's
// schema_version table.
//
// The version is a table row, not PRAGMA user_version, for three reasons:
// the storage engine refuses PRAGMA assignments inside a write job, so a
// pragma could not be set in the job that creates or upgrades the schema,
// and the version would not commit atomically with it; the row also holds
// compatible_from, which rollback-safe upgrades need (ADR-0059 Decision 8,
// G6: an older varlatchd may open a database a rollback-safe newer release
// wrote); and it says which release created and last changed the schema.
//
// Until the first Go release, schema.sql changes in place under version 1;
// a database made by a development build is not upgraded. From that
// release on, every change to schema.sql raises this number and comes with
// its upgrade, which `varlatch upgrade` (step 6) runs.
const SchemaVersion = 1

// ErrNotVarlatch is returned by Init for a database that has tables but no
// schema version: not one varlatchd created.
var ErrNotVarlatch = errors.New("db: the database has tables but no schema_version: not a varlatchd database")

// VersionError is returned by Init when the database's schema is one this
// varlatchd cannot use: older than SchemaVersion (it needs an upgrade), or
// newer and not compatible with it (written by a release that was not
// rollback-safe with respect to this one).
type VersionError struct {
	Database       int64 // the database's schema version
	CompatibleFrom int64 // the oldest version that may open it
	Binary         int64 // SchemaVersion
}

func (e *VersionError) Error() string {
	if e.Database < e.Binary {
		return fmt.Sprintf("db: the database's schema is version %d, older than this varlatchd's %d; run varlatch upgrade", e.Database, e.Binary)
	}
	return fmt.Sprintf("db: the database's schema is version %d, which needs a varlatchd that knows version %d or later (this one knows %d)",
		e.Database, e.CompatibleFrom, e.Binary)
}

// State is what Init found or made.
type State struct {
	Created        bool  // Init created the schema now
	Version        int64 // the database's schema version
	CompatibleFrom int64
}

// Init prepares the database for varlatchd, before anything else uses it.
//
// On a database with no tables (a new file) it creates the schema and
// records SchemaVersion, both in one write job: either all of it commits or
// none. On a database that has the schema it checks the recorded version:
// the same version is ready; a newer one is accepted when its
// compatible_from allows this varlatchd (a rollback-safe release wrote it);
// anything else is a *VersionError. A database with tables but no
// schema_version is ErrNotVarlatch. Init never changes an existing schema.
//
// release names the varlatchd release, recorded as the schema's creator
// (1 to 64 characters).
func Init(ctx context.Context, s *storage.DB, release string) (State, error) {
	if n := len(release); n < 1 || n > 64 {
		return State{}, errors.New("db: the release name must be 1 to 64 characters")
	}
	var st State
	err := s.Write(ctx, func(tx *storage.Tx) error {
		st = State{}
		var tables int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'").Scan(&tables); err != nil {
			return err
		}
		q := query.New(tx)
		if tables == 0 {
			if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
				return fmt.Errorf("db: creating the schema: %w", err)
			}
			now := time.Now().UnixMicro()
			if err := q.CreateSchemaVersion(ctx, query.CreateSchemaVersionParams{
				Version: SchemaVersion, CompatibleFrom: SchemaVersion,
				CreatedAt: now, CreatedByRelease: release, UpdatedAt: now, UpdatedByRelease: release,
			}); err != nil {
				return fmt.Errorf("db: recording the schema version: %w", err)
			}
			st = State{Created: true, Version: SchemaVersion, CompatibleFrom: SchemaVersion}
			return nil
		}
		var present int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'").Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			return ErrNotVarlatch
		}
		v, err := q.GetSchemaVersion(ctx)
		if err != nil {
			return fmt.Errorf("db: reading the schema version: %w", err)
		}
		st = State{Version: v.Version, CompatibleFrom: v.CompatibleFrom}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotVarlatch) {
			return State{}, ErrNotVarlatch
		}
		return State{}, err
	}
	if st.Version == SchemaVersion || (st.Version > SchemaVersion && st.CompatibleFrom <= SchemaVersion) {
		return st, nil
	}
	return st, &VersionError{Database: st.Version, CompatibleFrom: st.CompatibleFrom, Binary: SchemaVersion}
}
