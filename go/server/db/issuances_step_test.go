// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !g6fixture

package db

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/schemadiff"
)

// What starts what schema versions 2 to 6 added to schema.sql: what comes
// before is the version before's schema (0.50.0-rc.1's is version 1, 0.50.0's
// version 2, 0.50.2's version 3; CI's G6 job checks against a tag's own
// file).
const (
	rc1Marker = "\n-- Certificate issuances for the public HTTPS name"
	v2Marker  = "\n-- Audit reads of the repair of Capabilities"
	v3Marker  = "\n-- Exercise-only credentials and tokens exchanged once"
	v4Marker  = "\n-- One-time codes given (ADR-0061)"
	v5Marker  = "\n-- OAuth connections"
)

// schemaBefore is schema.sql as released before marker's section.
func schemaBefore(t *testing.T, marker string) string {
	t.Helper()
	i := strings.Index(schemaSQL, marker)
	if i < 0 {
		t.Fatalf("schema.sql has no section %q", marker)
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
	rc1 := schemaBefore(t, rc1Marker)
	exec(t, older, rc1,
		"INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release) VALUES (1, 1, 1, '0.50.0-rc.1', 1, '0.50.0-rc.1')")
	up, err := Upgrade(ctx, older, testRelease)
	if err != nil || !up.Changed || up.From != 1 || up.To != SchemaVersion || up.CompatibleFrom != 1 {
		t.Fatalf("%+v, %v", up, err)
	}
	if changes, err := schemadiff.Diff(ctx, schemaOf(t, openDB(t)), schemaOf(t, older)); err != nil || len(changes) != 0 {
		t.Fatalf("the upgraded schema differs from a new one: %v, %v", changes, err)
	}
	changes, err := schemadiff.Diff(ctx, rc1, schemaBefore(t, v2Marker))
	if err != nil || schemadiff.Breaks(changes) || len(changes) != 2 {
		t.Fatalf("version 2's change: %v, %v", changes, err)
	}
	// The table takes rows once upgraded.
	exec(t, older, "INSERT INTO certificate_issuances (name, started_at) VALUES ('vault.varlatch.test', 1)")
}

// Schema version 3: a database 0.50.0 made (schema 2) upgrades to the
// schema a new database gets, and the step only adds three non-unique
// indexes, so it is rollback-safe: compatible_from stays 1. The upgraded
// database keeps its events, and the indexes take new ones.
func TestV2DatabaseUpgradesToVersion3(t *testing.T) {
	ctx := context.Background()
	older := openFile(t, filepath.Join(t.TempDir(), "v2.db"))
	defer older.Close()
	v2 := schemaBefore(t, v2Marker)
	exec(t, older, v2,
		"INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release) VALUES (2, 1, 1, '0.50.0', 1, '0.50.0')")
	up, err := Upgrade(ctx, older, testRelease)
	if err != nil || !up.Changed || up.From != 2 || up.To != SchemaVersion || up.CompatibleFrom != 1 {
		t.Fatalf("%+v, %v", up, err)
	}
	if changes, err := schemadiff.Diff(ctx, schemaOf(t, openDB(t)), schemaOf(t, older)); err != nil || len(changes) != 0 {
		t.Fatalf("the upgraded schema differs from a new one: %v, %v", changes, err)
	}
	changes, err := schemadiff.Diff(ctx, v2, schemaBefore(t, v3Marker))
	if err != nil || schemadiff.Breaks(changes) || len(changes) != 3 {
		t.Fatalf("version 3's change: %v, %v", changes, err)
	}
	for _, c := range changes {
		if c.Class != schemadiff.Additive || !strings.HasPrefix(c.Object, "index audit_events_") && c.Object != "index capabilities_live_idx" {
			t.Fatalf("version 3's change: %v", c)
		}
	}
}

// A database that reached any earlier schema version upgrades to this one,
// to the schema a new database gets, and every step is additive. Each step
// is one a database got when it reached its version: what a later version
// adds is a step of its own, never more of that one.
func TestEveryEarlierVersionUpgrades(t *testing.T) {
	ctx := context.Background()
	markers := []string{rc1Marker, v2Marker, v3Marker, v4Marker, v5Marker}
	if len(markers) != SchemaVersion-1 {
		t.Fatalf("%d markers for schema version %d", len(markers), SchemaVersion)
	}
	for i, marker := range markers {
		from, before, next := int64(i+1), schemaBefore(t, marker), schemaSQL
		if i+1 < len(markers) {
			next = schemaBefore(t, markers[i+1])
		}
		if changes, err := schemadiff.Diff(ctx, before, next); err != nil || schemadiff.Breaks(changes) || len(changes) == 0 {
			t.Fatalf("version %d's change: %v, %v", from+1, changes, err)
		}
		older := openFile(t, filepath.Join(t.TempDir(), "older.db"))
		defer older.Close()
		exec(t, older, before, fmt.Sprintf("INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release) VALUES (%d, 1, 1, 'earlier', 1, 'earlier')", from))
		up, err := Upgrade(ctx, older, testRelease)
		if err != nil || !up.Changed || up.From != from || up.To != SchemaVersion || up.CompatibleFrom != 1 {
			t.Fatalf("from %d: %+v, %v", from, up, err)
		}
		if changes, err := schemadiff.Diff(ctx, schemaOf(t, openDB(t)), schemaOf(t, older)); err != nil || len(changes) != 0 {
			t.Fatalf("from %d: the upgraded schema differs from a new one: %v, %v", from, changes, err)
		}
		// The new tables take rows, checked.
		key := strings.Repeat("0f", 32)
		exec(t, older, "INSERT INTO oidc_token_uses (token_key, used_at, expires_at) VALUES ('"+key+"', 1, 2)")
		for _, bad := range []string{
			"INSERT INTO oidc_token_uses (token_key, used_at, expires_at) VALUES ('" + key + "', 1, 2)",
			"INSERT INTO oidc_token_uses (token_key, used_at, expires_at) VALUES ('jti', 1, 2)",
			"INSERT INTO exercise_credentials (credential_id, oidc_binding_id) VALUES ('crd_none', 'oib_none')",
			"INSERT INTO one_time_codes_given (version_id, step) VALUES ('ver_none', 1)",
			"INSERT INTO oauth_connections (value_id, version_id, status) VALUES ('val_none', 'ver_none', 'connected')",
		} {
			if err := tryExec(older, bad); err == nil {
				t.Errorf("from %d: accepted: %s", from, bad)
			}
		}
	}
}
