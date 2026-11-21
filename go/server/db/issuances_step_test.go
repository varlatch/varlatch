// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !g6fixture

package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/schemadiff"
)

// rc1Marker starts what schema version 2 added to schema.sql: what comes
// before it is 0.50.0-rc.1's schema (CI's G6 job checks against the tag's
// own file).
const rc1Marker = "\n-- Certificate issuances for the public HTTPS name"

// rc1Schema is schema.sql as 0.50.0-rc.1 released it (schema version 1).
func rc1Schema(t *testing.T) string {
	t.Helper()
	i := strings.Index(schemaSQL, rc1Marker)
	if i < 0 {
		t.Fatal("schema.sql has no certificate_issuances section")
	}
	return schemaSQL[:i] + "\n"
}

// schemaOf is the schema a database holds, as statements.
func schemaOf(t *testing.T, s *storage.DB) string {
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

// Schema version 2: a database 0.50.0-rc.1 made (schema 1) upgrades to the
// schema a new database gets, and the step only adds (a table and its
// index), so it is rollback-safe: compatible_from stays 1.
func TestRC1DatabaseUpgradesToVersion2(t *testing.T) {
	ctx := context.Background()
	older := openFile(t, filepath.Join(t.TempDir(), "rc1.db"))
	defer older.Close()
	exec(t, older, rc1Schema(t),
		"INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release) VALUES (1, 1, 1, '0.50.0-rc.1', 1, '0.50.0-rc.1')")
	up, err := Upgrade(ctx, older, testRelease)
	if err != nil || !up.Changed || up.From != 1 || up.To != 2 || up.CompatibleFrom != 1 {
		t.Fatalf("%+v, %v", up, err)
	}
	if changes, err := schemadiff.Diff(ctx, schemaOf(t, openDB(t)), schemaOf(t, older)); err != nil || len(changes) != 0 {
		t.Fatalf("the upgraded schema differs from a new one: %v, %v", changes, err)
	}
	changes, err := schemadiff.Diff(ctx, rc1Schema(t), schemaSQL)
	if err != nil || schemadiff.Breaks(changes) || len(changes) != 2 {
		t.Fatalf("version 2's change: %v, %v", changes, err)
	}
	// The table takes rows once upgraded.
	exec(t, older, "INSERT INTO certificate_issuances (name, started_at) VALUES ('vault.varlatch.test', 1)")
}
