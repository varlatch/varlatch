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

// Schema returns the statements that create the schema of version
// SchemaVersion on an empty database: schema.sql (and, in G6's fixture
// build, its synthetic change).
func Schema() string { return schemaSQL + schemaExtra }

// SchemaVersion, CompatibleFrom and the upgrade steps are in version.go
// (and, in a build with the g6fixture tag, version_g6fixture.go: G6's
// synthetic release).

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
// records SchemaVersion and CompatibleFrom, all in one write job: either
// all of it commits or none. On a database that has the schema it checks
// the recorded version: the same version is ready; a newer one is accepted
// when its compatible_from allows this varlatchd (a rollback-safe release
// wrote it); anything else is a *VersionError (an older one needs
// Upgrade). A database with tables but no schema_version is
// ErrNotVarlatch. Init never changes an existing schema.
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
			if _, err := tx.ExecContext(ctx, Schema()); err != nil {
				return fmt.Errorf("db: creating the schema: %w", err)
			}
			now := time.Now().UnixMicro()
			if err := q.CreateSchemaVersion(ctx, query.CreateSchemaVersionParams{
				Version: SchemaVersion, CompatibleFrom: CompatibleFrom,
				CreatedAt: now, CreatedByRelease: release, UpdatedAt: now, UpdatedByRelease: release,
			}); err != nil {
				return fmt.Errorf("db: recording the schema version: %w", err)
			}
			st = State{Created: true, Version: SchemaVersion, CompatibleFrom: CompatibleFrom}
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
