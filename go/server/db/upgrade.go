// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// Step upgrades the schema from version To-1 to To: SQL runs in the
// upgrade's write job, schema changes and the rows they need together.
type Step struct {
	To int64
	// CompatibleFrom is the oldest schema version whose varlatchd may open
	// the database after this step: To-1's (or earlier) for a rollback-safe
	// step, To for any other. It never goes down from one step to the next.
	// A rollback-safe step may only make the changes a rollback-safe
	// release may (server/db/schemadiff): G6's release check holds every
	// step to its own declaration, against the schema just before it, as
	// varlatchd serve applies a rollback-safe upgrade at start in the image.
	CompatibleFrom int64
	SQL            string
}

// ErrNoDatabase is returned by Upgrade for a database with no tables:
// there is nothing to upgrade (serve or setup creates it).
var ErrNoDatabase = errors.New("db: the database has no schema yet: nothing to upgrade")

// Upgraded is what Upgrade found and did.
type Upgraded struct {
	From           int64 // the database's schema version before
	To             int64 // and after
	CompatibleFrom int64 // the database's compatible_from after
	Changed        bool  // a step ran
}

// Upgrade brings the database's schema to SchemaVersion: every step from
// its recorded version on, then the new version, CompatibleFrom and release
// recorded, all in one write job, so either all of it commits or none. A
// database already at SchemaVersion, or at a newer version this varlatchd
// may open (a rollback-safe release wrote it), is left as it is. A newer
// one it may not open is a *VersionError, a database without tables
// ErrNoDatabase, one without schema_version ErrNotVarlatch.
//
// It runs offline (`varlatchd admin schema upgrade`, under the data
// directory's lock), never while varlatchd serves: ADR-0059 Decision 8
// runs it on a copy of the database first (`varlatch upgrade`).
func Upgrade(ctx context.Context, s *storage.DB, release string) (Upgraded, error) {
	return upgrade(ctx, s, release, steps, SchemaVersion, CompatibleFrom, false)
}

// Steps returns a copy of this varlatchd's upgrade steps, in order:
// Steps()[i] upgrades version i+1 to i+2.
func Steps() []Step { return slices.Clone(steps) }

// NotRollbackSafeError is returned by UpgradeIfRollbackSafe for a database
// whose upgrade would not be rollback-safe: after it, the database would
// open only in a varlatchd of schema CompatibleFrom or later, newer than
// the schema it has now (Database), so the release that wrote it could no
// longer open it. Nothing was changed.
type NotRollbackSafeError struct {
	Database       int64 // the database's schema version
	CompatibleFrom int64 // the oldest version that may open it after the upgrade
	Binary         int64 // SchemaVersion
}

func (e *NotRollbackSafeError) Error() string {
	return fmt.Sprintf("db: upgrading the database's schema from version %d to %d is not rollback-safe: afterwards only varlatchd of schema %d and later opens it, so the release that wrote it could not open it again",
		e.Database, e.Binary, e.CompatibleFrom)
}

// RollbackSafeFrom reports whether an upgrade from schema version from to
// SchemaVersion is rollback-safe: the varlatchd of schema from still opens
// the database after it (CompatibleFrom is not newer than from).
func RollbackSafeFrom(from int64) bool { return CompatibleFrom <= from }

// UpgradeIfRollbackSafe is Upgrade, for a database whose upgrade is
// rollback-safe only: when the steps from its recorded version would raise
// compatible_from above that version, it changes nothing and returns a
// *NotRollbackSafeError. It reads the version and runs the steps in the
// same write job as Upgrade, so the check and the upgrade see the same
// database.
//
// varlatchd serve runs it at start in the single-container image, where an
// installation is upgraded by deploying a newer image's digest and the way
// back is the previous digest (go/server/daemon schemaAtStart): for a
// rollback-safe upgrade, that previous digest still opens the result, so
// going back needs no restore.
func UpgradeIfRollbackSafe(ctx context.Context, s *storage.DB, release string) (Upgraded, error) {
	return upgrade(ctx, s, release, steps, SchemaVersion, CompatibleFrom, true)
}

func upgrade(ctx context.Context, s *storage.DB, release string, steps []Step, target, compatibleFrom int64, rollbackSafeOnly bool) (Upgraded, error) {
	if n := len(release); n < 1 || n > 64 {
		return Upgraded{}, errors.New("db: the release name must be 1 to 64 characters")
	}
	if err := checkSteps(steps, target, compatibleFrom); err != nil {
		return Upgraded{}, err
	}
	var up Upgraded
	err := s.Write(ctx, func(tx *storage.Tx) error {
		up = Upgraded{}
		var tables int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'").Scan(&tables); err != nil {
			return err
		}
		if tables == 0 {
			return ErrNoDatabase
		}
		var present int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'").Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			return ErrNotVarlatch
		}
		v, err := query.New(tx).GetSchemaVersion(ctx)
		if err != nil {
			return fmt.Errorf("db: reading the schema version: %w", err)
		}
		up = Upgraded{From: v.Version, To: v.Version, CompatibleFrom: v.CompatibleFrom}
		if v.Version < 1 || v.CompatibleFrom < 1 || v.CompatibleFrom > v.Version {
			// A row no varlatchd writes (schema.sql's checks keep it out; a
			// database changed by hand may hold one).
			return fmt.Errorf("db: the recorded version %d (compatible from %d) is not a varlatch schema version", v.Version, v.CompatibleFrom)
		}
		if v.Version > target {
			if v.CompatibleFrom <= target {
				return nil
			}
			return &VersionError{Database: v.Version, CompatibleFrom: v.CompatibleFrom, Binary: target}
		}
		if v.Version == target {
			return nil
		}
		if rollbackSafeOnly && compatibleFrom > v.Version {
			return &NotRollbackSafeError{Database: v.Version, CompatibleFrom: compatibleFrom, Binary: target}
		}
		for _, st := range steps[v.Version-1:] {
			if _, err := tx.ExecContext(ctx, st.SQL); err != nil {
				return fmt.Errorf("db: upgrading the schema to version %d: %w", st.To, err)
			}
		}
		res, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = ?, compatible_from = ?, updated_at = ?, updated_by_release = ? WHERE singleton = 1",
			target, compatibleFrom, time.Now().UnixMicro(), release)
		if err != nil {
			return fmt.Errorf("db: recording the schema version: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("db: recording the schema version: %d rows, %v", n, err)
		}
		up = Upgraded{From: v.Version, To: target, CompatibleFrom: compatibleFrom, Changed: true}
		return nil
	})
	if err != nil {
		var verr *VersionError
		var nerr *NotRollbackSafeError
		switch {
		case errors.Is(err, ErrNoDatabase), errors.Is(err, ErrNotVarlatch), errors.As(err, &verr), errors.As(err, &nerr):
			return up, unwrapped(err)
		}
		return up, err
	}
	return up, nil
}

// unwrapped returns the sentinel or *VersionError a write job's error
// carries, so callers compare and print it as Init's.
func unwrapped(err error) error {
	var verr *VersionError
	var nerr *NotRollbackSafeError
	switch {
	case errors.As(err, &verr):
		return verr
	case errors.As(err, &nerr):
		return nerr
	case errors.Is(err, ErrNoDatabase):
		return ErrNoDatabase
	case errors.Is(err, ErrNotVarlatch):
		return ErrNotVarlatch
	}
	return err
}

// checkSteps checks the steps against the version they reach: one per
// version from 2 to target, in order, each CompatibleFrom between 1 and its
// To and never lower than the step before, the last one's compatibleFrom.
func checkSteps(steps []Step, target, compatibleFrom int64) error {
	if int64(len(steps)) != target-1 {
		return fmt.Errorf("db: %d upgrade steps for schema version %d; want %d", len(steps), target, target-1)
	}
	last := int64(1)
	for i, st := range steps {
		if st.To != int64(i)+2 {
			return fmt.Errorf("db: upgrade step %d goes to version %d; want %d", i, st.To, i+2)
		}
		if st.CompatibleFrom < last || st.CompatibleFrom > st.To {
			return fmt.Errorf("db: upgrade step to version %d: compatibleFrom %d is not between %d and %d", st.To, st.CompatibleFrom, last, st.To)
		}
		last = st.CompatibleFrom
	}
	if compatibleFrom != last {
		return fmt.Errorf("db: CompatibleFrom is %d; the last upgrade step's is %d", compatibleFrom, last)
	}
	return nil
}
