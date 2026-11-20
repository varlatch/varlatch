// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g6fixture

package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/schemadiff"
)

// dump is the schema a database holds, as statements.
func dump(t *testing.T, s *storage.DB) string {
	t.Helper()
	rows, err := s.Reader().QueryContext(context.Background(), "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END, rowid")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err != nil {
			t.Fatal(err)
		}
		b.WriteString(q + ";\n")
	}
	return b.String()
}

// G6's fixture release: a database of the schema before it, upgraded, is
// the schema a new database of the fixture gets, and the fixture's change is
// additive only.
func TestTheG6FixtureUpgradesToItsSchema(t *testing.T) {
	ctx := context.Background()
	older := openFile(t, filepath.Join(t.TempDir(), "older.db"))
	defer older.Close()
	exec(t, older, schemaSQL,
		"INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release) VALUES (1, 1, 1, 'previous', 1, 'previous')")
	up, err := Upgrade(ctx, older, testRelease)
	if err != nil || !up.Changed || up.From != 1 || up.To != 2 || up.CompatibleFrom != CompatibleFrom {
		t.Fatalf("%+v, %v", up, err)
	}
	fresh := openDB(t)
	changes, err := schemadiff.Diff(ctx, dump(t, fresh), dump(t, older))
	if err != nil || len(changes) != 0 {
		t.Fatalf("the upgraded schema differs from a new one: %v, %v", changes, err)
	}
	changes, err = schemadiff.Diff(ctx, schemaSQL, Schema())
	if err != nil || schemadiff.Breaks(changes) || len(changes) != 2 {
		t.Fatalf("the fixture's change: %v, %v", changes, err)
	}
	// release/testdata/g6/additive.sql, which the releasecheck fixtures
	// append to schema.sql, is this build's change.
	additive, err := os.ReadFile(filepath.Join("..", "..", "release", "testdata", "g6", "additive.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if changes, err := schemadiff.Diff(ctx, schemaSQL+string(additive), Schema()); err != nil || len(changes) != 0 {
		t.Fatalf("additive.sql is not the fixture's change: %v, %v", changes, err)
	}
	var n int
	if err := older.Reader().QueryRowContext(ctx, "SELECT count(*) FROM g6_fixture").Scan(&n); err != nil || n != 1 {
		t.Fatalf("the fixture's row: %d, %v", n, err)
	}
}
